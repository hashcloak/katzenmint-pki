package katzenmint

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/cosmos/iavl"
	"github.com/hashcloak/katzenmint-pki/config"
	"github.com/hashcloak/katzenmint-pki/s11n"
	katvoting "github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/pki"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
	"github.com/tendermint/tendermint/crypto/merkle"
	pc "github.com/tendermint/tendermint/proto/tendermint/crypto"
	dbm "github.com/tendermint/tm-db"
)

const genesisEpoch uint64 = 1
const epochInterval int64 = 5

var (
	errDocDescriptor = errors.New("insufficient descriptors uploaded")
	errDocProvider   = errors.New("no providers uploaded")
)

type descriptor struct {
	desc *pki.MixDescriptor
	raw  []byte
}

type document struct {
	doc *pki.Document
	raw []byte
}

type KatzenmintState struct {
	sync.RWMutex
	appHash          []byte
	blockHeight      int64
	currentEpoch     uint64
	epochStartHeight int64

	tree *iavl.MutableTree

	layers           int
	minNodesPerLayer int
	parameters       *katvoting.Parameters
	documents        map[uint64]*document
	descriptors      map[uint64]map[[eddsa.PublicKeySize]byte]*descriptor
	validators       map[string]pc.PublicKey
	validatorUpdates []abcitypes.ValidatorUpdate

	deferCommit     []func()
	prevCommitError error
}

func NewKatzenmintState(kConfig *config.Config, db dbm.DB) *KatzenmintState {
	// TODO: should load the current state from database
	tree, err := iavl.NewMutableTree(db, 100)
	if err != nil {
		panic(fmt.Errorf("error creating iavl tree"))
	}
	version, err := tree.Load()
	if err != nil {
		panic(fmt.Errorf("error loading iavl tree"))
	}
	state := &KatzenmintState{
		appHash:          tree.Hash(),
		blockHeight:      version,
		tree:             tree,
		layers:           kConfig.Layers,
		minNodesPerLayer: kConfig.MinNodesPerLayer,
		parameters:       &kConfig.Parameters,
		documents:        make(map[uint64]*document),
		descriptors:      make(map[uint64]map[[eddsa.PublicKeySize]byte]*descriptor),
		validators:       make(map[string]pc.PublicKey),
		validatorUpdates: make([]abcitypes.ValidatorUpdate, 0),
		deferCommit:      make([]func(), 0),
		prevCommitError:  nil,
	}

	// Load current epoch and its start height
	epochInfoValue, err := state.Get([]byte(epochInfoKey))
	if version == 0 {
		state.currentEpoch = genesisEpoch
		state.epochStartHeight = 0
	} else if err != nil || epochInfoValue == nil || len(epochInfoValue) != 16 {
		panic("error loading the current epoch number and its starting height")
	} else {
		state.currentEpoch, _ = binary.Uvarint(epochInfoValue[:8])
		state.epochStartHeight, _ = binary.Varint(epochInfoValue[8:])
	}

	// Load documents
	end := make([]byte, len(documentsBucket))
	copy(end, []byte(documentsBucket))
	end = append(end, 0xff)
	_ = tree.IterateRange([]byte(documentsBucket), end, true, func(key, value []byte) bool {
		id, epoch := unpackStorageKey(key)
		if id == nil {
			// panic(fmt.Errorf("unable to unpack storage key %v", key))
			return true
		}
		if doc, err := s11n.VerifyAndParseDocument(value); err == nil {
			state.documents[epoch] = &document{doc: doc, raw: value}
		}
		return false
	})

	// Load descriptors
	end = make([]byte, len(descriptorsBucket))
	copy(end, []byte(descriptorsBucket))
	end = append(end, 0xff)
	_ = tree.IterateRange([]byte(descriptorsBucket), end, true, func(key, value []byte) bool {
		id, epoch := unpackStorageKey(key)
		if id == nil {
			// panic(fmt.Errorf("unable to unpack storage key %v", key))
			return true
		}
		verifier, err := s11n.GetVerifierFromDescriptor(value)
		if err == nil {
			if !bytes.Equal(verifier.Identity(), id) {
				// panic(fmt.Errorf("storage key id %v has another descriptor id %v", id, verifier.Identity()))
				return true
			}
			desc, err := s11n.VerifyAndParseDescriptor(verifier, value, epoch)
			if err == nil {
				var pubkey [32]byte
				copy(pubkey[:], id)
				if _, ok := state.descriptors[epoch]; !ok {
					state.descriptors[epoch] = make(map[[32]byte]*descriptor)
				}
				state.descriptors[epoch][pubkey] = &descriptor{desc: desc, raw: value}
			}
		}
		return false
	})

	// Load validators
	end = make([]byte, len(authoritiesBucket))
	copy(end, []byte(authoritiesBucket))
	end = append(end, 0xff)
	_ = tree.IterateRange([]byte(authoritiesBucket), end, true, func(key, value []byte) bool {
		id, _ := unpackStorageKey(key)
		if id == nil {
			// panic(fmt.Errorf("unable to unpack storage key %v", key))
			return true
		}
		auth, err := VerifyAndParseAuthority(value)
		if err != nil {
			// panic(fmt.Errorf("error parsing authority: %v", err))
			return true
		}
		var protopk pc.PublicKey
		err = protopk.Unmarshal(id)
		if err != nil {
			// panic(fmt.Errorf("error unmarshal proto: %v", err))
			return true
		}
		pk, err := cryptoenc.PubKeyFromProto(protopk)
		if err != nil {
			panic(fmt.Errorf("error extraction from proto: %v", err))
			// return true
		}
		state.validators[string(pk.Address())] = protopk
		if !bytes.Equal(auth.IdentityKey.Bytes(), protopk.GetEd25519()) {
			panic(fmt.Errorf("storage key id %v has another authority id %v", id, auth.IdentityKey.Bytes()))
			// return false
		}
		return false
	})

	return state
}

func (state *KatzenmintState) BeginBlock() {
	state.Lock()
	defer state.Unlock()
	state.validatorUpdates = make([]abcitypes.ValidatorUpdate, 0)
}

func (state *KatzenmintState) Commit() ([]byte, error) {
	state.Lock()
	defer state.Unlock()

	var errDoc error = nil
	if len(state.deferCommit) > 0 {
		for _, def := range state.deferCommit {
			def()
		}
		state.deferCommit = make([]func(), 0)
	}
	state.blockHeight++
	currentEpoch := state.currentEpoch
	if state.newDocumentRequired() {
		var doc *document
		if doc, errDoc = state.generateDocument(); errDoc == nil {
			errDoc = state.updateDocument(doc.raw, doc.doc, state.currentEpoch)
			if errDoc == nil {
				state.currentEpoch++
				state.epochStartHeight = state.blockHeight
				// TODO: Prune related descriptors
			}
		}
	}
	epochInfoValue := make([]byte, 16)
	binary.PutUvarint(epochInfoValue[:8], currentEpoch)
	binary.PutVarint(epochInfoValue[8:], state.epochStartHeight)
	_ = state.Set([]byte(epochInfoKey), epochInfoValue)
	appHash, _, err := state.tree.SaveVersion()
	if err != nil {
		return nil, err
	}
	state.appHash = appHash

	if errDoc == errDocDescriptor || errDoc == errDocProvider {
		// Report these errors when they first appear
		if errDoc == state.prevCommitError {
			errDoc = nil
		} else {
			state.prevCommitError = errDoc
		}
	} else {
		errDoc = nil
	}
	return appHash, errDoc
}

func (state *KatzenmintState) newDocumentRequired() bool {
	// TODO: determine when to finish the current epoch
	return state.blockHeight > state.epochStartHeight+epochInterval
}

func (s *KatzenmintState) generateDocument() (*document, error) {
	// Cannot lock here

	// Carve out the descriptors between providers and nodes.
	var providersDesc, nodes []*descriptor
	for _, v := range s.descriptors[s.currentEpoch] {
		if v.desc.Layer == pki.LayerProvider {
			providersDesc = append(providersDesc, v)
		} else {
			nodes = append(nodes, v)
		}
	}

	// Assign nodes to layers. # No randomness yet.
	var topology [][][]byte
	if len(nodes) < s.layers*s.minNodesPerLayer {
		return nil, errDocDescriptor
	}
	sortNodesByPublicKey(nodes)
	if d, ok := s.documents[s.currentEpoch-1]; ok {
		topology = generateTopology(nodes, d.doc, s.layers)
	} else {
		topology = generateRandomTopology(nodes, s.layers)
	}

	// Sort the providers
	var providers [][]byte
	if len(providersDesc) == 0 {
		return nil, errDocProvider
	}
	sortNodesByPublicKey(providersDesc)
	for _, v := range providersDesc {
		providers = append(providers, v.raw)
	}

	// Build the Document.
	doc := &s11n.Document{
		Epoch:             s.currentEpoch,
		GenesisEpoch:      genesisEpoch,
		SendRatePerMinute: s.parameters.SendRatePerMinute,
		Mu:                s.parameters.Mu,
		MuMaxDelay:        s.parameters.MuMaxDelay,
		LambdaP:           s.parameters.LambdaP,
		LambdaPMaxDelay:   s.parameters.LambdaPMaxDelay,
		LambdaL:           s.parameters.LambdaL,
		LambdaLMaxDelay:   s.parameters.LambdaLMaxDelay,
		LambdaD:           s.parameters.LambdaD,
		LambdaDMaxDelay:   s.parameters.LambdaDMaxDelay,
		LambdaM:           s.parameters.LambdaM,
		LambdaMMaxDelay:   s.parameters.LambdaMMaxDelay,
		Topology:          topology,
		Providers:         providers,
	}

	// TODO: what to do with shared random value?

	// Serialize the Document.
	serialized, err := s11n.SerializeDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize document: %v", err)
	}

	// Ensure the document is sane.
	pDoc, err := s11n.VerifyAndParseDocument(serialized)
	if err != nil {
		return nil, fmt.Errorf("signed document failed validation: %v", err)
	}
	if pDoc.Epoch != s.currentEpoch {
		return nil, fmt.Errorf("signed document has invalid epoch: %v", pDoc.Epoch)
	}
	ret := &document{
		doc: pDoc,
		raw: serialized,
	}
	return ret, nil
}

func (state *KatzenmintState) latestEpoch(height int64) ([]byte, merkle.ProofOperator, error) {
	key := []byte(epochInfoKey)
	val, proof, err := state.tree.GetVersionedWithProof(key, height)
	if err != nil {
		return nil, nil, err
	}
	if len(val) != 16 {
		return nil, nil, fmt.Errorf("error fetching latest epoch for height %v", height)
	}
	valueOp := iavl.NewValueOp(key, proof)
	return val, valueOp, nil

}

func (state *KatzenmintState) documentForEpoch(epoch uint64, height int64) ([]byte, merkle.ProofOperator, error) {
	// TODO: postpone the document for some blocks?
	// var postponDeadline = 10

	e := make([]byte, 8)
	binary.PutUvarint(e, epoch)
	key := storageKey(documentsBucket, e, epoch)
	doc, proof, err := state.tree.GetVersionedWithProof(key, height)
	if err != nil {
		return nil, nil, err
	}
	if doc == nil {
		// TODO: replace how we get `now`
		now, _, _ := epochtime.Now()
		if epoch <= now {
			return nil, nil, fmt.Errorf("document for epoch %d was not generated and will never exist", epoch)
		}
		if epoch > now+1 {
			return nil, nil, fmt.Errorf("requesting document for a too future epoch %d", epoch)
		}
		return nil, nil, fmt.Errorf("document for epoch %d is not ready yet", epoch)
	}
	valueOp := iavl.NewValueOp(key, proof)
	return doc, valueOp, nil
}

func (state *KatzenmintState) isAuthorized(addr string) bool {
	return true
}

func (state *KatzenmintState) GetAuthorized(addr string) (pc.PublicKey, bool) {
	pubkey, ok := state.validators[addr]
	return pubkey, ok
}

func (state *KatzenmintState) isDescriptorAuthorized(desc *pki.MixDescriptor) bool {
	return true
	/*
		pk := desc.IdentityKey.ByteArray()
		switch desc.Layer {
		case 0:
		 	return state.authorizedMixes[pk]
		case pki.LayerProvider:
			// check authorities, should use validator address
			_, ok := state.validators[bytesToAddress(pk)]
			return ok
		default:
			return false
		}
	*/
}

func (state *KatzenmintState) isDocumentAuthorized(doc *pki.Document) bool {
	return true
}

func (state *KatzenmintState) Set(key []byte, value []byte) error {
	state.tree.Set(key, value)
	return nil
}

func (state *KatzenmintState) Delete(key []byte) error {
	_, success := state.tree.Remove(key)
	if !success {
		return fmt.Errorf("remove from database failed")
	}
	return nil
}

func (state *KatzenmintState) Get(key []byte) ([]byte, error) {
	_, val := state.tree.Get(key)
	if val == nil {
		return nil, fmt.Errorf("key '%v' does not exist", key)
	}
	ret := make([]byte, len(val))
	copy(ret, val)
	return ret, nil
}

// Note: Caller ensures that the epoch is the current epoch +- 1.
func (state *KatzenmintState) updateMixDescriptor(rawDesc []byte, desc *pki.MixDescriptor, epoch uint64) (err error) {
	state.Lock()
	defer state.Unlock()

	pk := desc.IdentityKey.ByteArray()

	// Get the public key -> descriptor map for the epoch.
	m, ok := state.descriptors[epoch]
	if !ok {
		m = make(map[[eddsa.PublicKeySize]byte]*descriptor)
		state.descriptors[epoch] = m
	}

	// Check for redundant uploads.
	if d, ok := m[pk]; ok {
		if d.raw == nil {
			return fmt.Errorf("state: Wtf, raw field of descriptor for epoch %v is nil", epoch)
		}
		// If the descriptor changes, then it will be rejected to prevent
		// nodes from reneging on uploads.
		if !bytes.Equal(d.raw, rawDesc) {
			return fmt.Errorf("state: Node %v: Conflicting descriptor for epoch %v", desc.IdentityKey, epoch)
		}

		// Redundant uploads that don't change are harmless.
		return nil
	}

	// Ok, this is a new descriptor.
	if state.documents[epoch] != nil {
		// If there is a document already, the descriptor is late, and will
		// never appear in a document, so reject it.
		return fmt.Errorf("state: Node %v: Late descriptor upload for for epoch %v", desc.IdentityKey, epoch)
	}

	// Persist the raw descriptor to disk.
	key := storageKey(descriptorsBucket, desc.IdentityKey.Bytes(), epoch)
	if err := state.Set(key, rawDesc); err != nil {
		return err
	}

	// Store the raw descriptor and the parsed struct.
	state.deferCommit = append(state.deferCommit, func() {
		d := new(descriptor)
		d.desc = desc
		d.raw = rawDesc
		m[pk] = d
	})

	/*
		id := hex.EncodeToString(desc.IdentityKey.Bytes())
		fmt.Printf("Node %s: Successfully submitted descriptor for epoch %v.", id, epoch)
	*/
	return
}

// Note: Caller ensures that the epoch is the current epoch +- 1.
func (state *KatzenmintState) updateDocument(rawDoc []byte, doc *pki.Document, epoch uint64) (err error) {
	// Cannot lock here

	// Get the public key -> document map for the epoch.
	m, ok := state.documents[epoch]
	if ok {
		if !bytes.Equal(m.raw, rawDoc) {
			return fmt.Errorf("state: Conflicting document for epoch %v", epoch)
		}
		// Redundant uploads that don't change are harmless.
		return nil
	}

	e := make([]byte, 8)
	binary.PutUvarint(e, epoch)

	// Persist the raw descriptor to disk.
	key := storageKey(documentsBucket, e, epoch)
	if err := state.Set(key, rawDoc); err != nil {
		return err
	}

	state.documents[epoch] = &document{doc: doc, raw: rawDoc}

	/*
		fmt.Printf("Node: Successfully submitted document for epoch %v.", epoch)
	*/
	return
}

func (state *KatzenmintState) updateAuthority(rawAuth []byte, v abcitypes.ValidatorUpdate) error {
	pubkey, err := cryptoenc.PubKeyFromProto(v.PubKey)
	if err != nil {
		return fmt.Errorf("can't decode public key: %w", err)
	}
	if _, ok := state.validators[string(pubkey.Address())]; ok {
		return fmt.Errorf("authority had been added")
	}
	protoPubKey, err := v.PubKey.Marshal()
	if err != nil {
		return err
	}
	key := storageKey(authoritiesBucket, protoPubKey, 0)

	if v.Power == 0 {
		// remove validator
		auth, err := state.Get(key)
		if err != nil {
			return err
		}
		if auth != nil {
			return fmt.Errorf("cannot remove non-existent validator %s", pubkey.Address())
		}
		if err = state.Delete(key); err != nil {
			return err
		}
		delete(state.validators, string(pubkey.Address()))
	} else {
		// TODO: make sure the voting power not exceed 1/3
		// add or update validator
		if rawAuth == nil && v.Power > 0 {
			auth := new(Authority)
			auth.Auth = "katzenmint"
			edPubkey := v.PubKey.GetEd25519()
			auth.IdentityKey = new(eddsa.PublicKey)
			if err := auth.IdentityKey.FromBytes(edPubkey); err != nil {
				return err
			}
			auth.LinkKey = auth.IdentityKey.ToECDH()
			auth.Power = v.Power
			if rawAuth, err = EncodeJson(auth); err != nil {
				return err
			}
		}
		if err := state.Set([]byte(key), rawAuth); err != nil {
			return err
		}
		state.validators[string(pubkey.Address())] = v.PubKey
	}

	state.validatorUpdates = append(state.validatorUpdates, v)

	return nil
}
