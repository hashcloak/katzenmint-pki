package katzenmint

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/cosmos/iavl"
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

var (
	defaultLayers           = 3
	defaultMinNodesPerLayer = 2
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
	appHash      []byte
	blockHeight  int64
	currentEpoch uint64
	genesisEpoch uint64

	tree *iavl.MutableTree

	layers           int
	minNodesPerLayer int
	parameters       *katvoting.Parameters
	documents        map[uint64]*document
	descriptors      map[uint64]map[[eddsa.PublicKeySize]byte]*descriptor
	validators       map[string]pc.PublicKey
	validatorUpdates []abcitypes.ValidatorUpdate

	deferCommit []func()
}

func NewKatzenmintState(db dbm.DB) *KatzenmintState {
	// TODO: should load the current state from database
	tree, err := iavl.NewMutableTree(db, 100)
	if err != nil {
		panic(fmt.Errorf("error creating iavl tree"))
	}
	return &KatzenmintState{
		appHash:          make([]byte, 0), // TODO: load
		blockHeight:      0,               // TODO: load
		currentEpoch:     1,               // TODO: load
		genesisEpoch:     1,               // TODO: load
		tree:             tree,
		layers:           defaultLayers,
		minNodesPerLayer: defaultMinNodesPerLayer,
		parameters:       &katvoting.Parameters{}, // TODO: load
		documents:        make(map[uint64]*document),
		descriptors:      make(map[uint64]map[[eddsa.PublicKeySize]byte]*descriptor),
		validatorUpdates: make([]abcitypes.ValidatorUpdate, 1),
		validators:       make(map[string]pc.PublicKey),
		deferCommit:      make([]func(), 0),
	}
}

func (state *KatzenmintState) BeginBlock() {
	state.Lock()
	defer state.Unlock()
	state.validatorUpdates = make([]abcitypes.ValidatorUpdate, 0)
}

func (state *KatzenmintState) Commit() []byte {
	state.Lock()
	defer state.Unlock()
	if len(state.deferCommit) > 0 {
		for _, def := range state.deferCommit {
			def()
		}
		state.deferCommit = make([]func(), 0)
	}
	state.blockHeight++
	state.currentEpoch++ // temporary
	if state.newDocumentRequired() {
		doc, err := state.generateDocument()
		if err != nil {
			// no logging yet?! use panic first for debug
			panic(err)
		}
		state.documents[state.currentEpoch] = doc
		// TODO: make checks and save them
		// TODO: and prune related descriptors
		state.currentEpoch++
	}
	appHash, _, err := state.tree.SaveVersion()
	if err != nil {
		// no logging yet?! use panic first for debug
		panic(err)
	}
	state.appHash = appHash
	return appHash
}

func (state *KatzenmintState) newDocumentRequired() bool {
	// TODO: determine when to finish the current epoch
	return false
}

func (s *KatzenmintState) generateDocument() (*document, error) {
	s.Lock()
	defer s.Unlock()

	// Carve out the descriptors between providers and nodes.
	var providers [][]byte
	var nodes []*descriptor
	for _, v := range s.descriptors[s.currentEpoch] {
		if v.desc.Layer == pki.LayerProvider {
			providers = append(providers, v.raw)
		} else {
			nodes = append(nodes, v)
		}
	}

	// Assign nodes to layers.
	var topology [][][]byte
	if len(nodes) < s.layers*s.minNodesPerLayer {
		return nil, fmt.Errorf("insufficient descriptors uploaded")
	}
	if d, ok := s.documents[s.currentEpoch-1]; ok {
		topology = generateTopology(nodes, d.doc, s.layers)
	} else {
		topology = generateRandomTopology(nodes, s.layers)
	}

	// Build the Document.
	doc := &s11n.Document{
		Epoch:             s.currentEpoch,
		GenesisEpoch:      s.genesisEpoch,
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

func (state *KatzenmintState) documentForEpoch(epoch uint64) ([]byte, merkle.ProofOperator, error) {
	// TODO: postpone the document for some blocks?
	// var postponDeadline = 10

	state.RLock()
	defer state.RUnlock()

	e := make([]byte, 8)
	binary.PutUvarint(e, epoch)
	key := storageKey(documentsBucket, e, epoch)
	doc, proof, err := state.tree.GetWithProof(key)
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
	if _, ok := state.validators[addr]; ok {
		return false
	}
	return true
}

func (state *KatzenmintState) GetAuthorized(addr string) (pc.PublicKey, bool) {
	pubkey, ok := state.validators[addr]
	return pubkey, ok
}

func (state *KatzenmintState) isDescriptorAuthorized(desc *pki.MixDescriptor) bool {
	pk := desc.IdentityKey.ByteArray()

	switch desc.Layer {
	// case 0:
	// 	return state.authorizedMixes[pk]
	case pki.LayerProvider:
		// check authorities, should use validator address
		_, ok := state.validators[bytesToAddress(pk)]
		return ok
	default:
		return false
	}
}

func (state *KatzenmintState) isDocumentAuthorized(doc *pki.Document) bool {
	if _, ok := state.documents[doc.Epoch]; ok {
		return true
	}
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
	state.Lock()
	defer state.Unlock()

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

	// Store the raw descriptor and the parsed struct.
	state.deferCommit = append(state.deferCommit, func() {
		d := new(document)
		d.doc = doc
		d.raw = rawDoc
		state.documents[epoch] = d
	})

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
	key := storageKey(authoritiesBucket, pubkey.Bytes(), 0)

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
		value := bytes.NewBuffer(make([]byte, 0))
		if err := abcitypes.WriteMessage(&v, value); err != nil {
			return fmt.Errorf("error encoding validator: %v", err)
		}
		if err = state.Set(key, value.Bytes()); err != nil {
			return err
		}
		if rawAuth != nil {
			// save payload into database
			if err := state.Set([]byte(key), rawAuth); err != nil {
				return err
			}
		}
		state.validators[string(pubkey.Address())] = v.PubKey
	}

	state.validatorUpdates = append(state.validatorUpdates, v)

	return nil
}
