package katzenmint

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	"github.com/cosmos/iavl"
	katvoting "github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/pki"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
	pc "github.com/tendermint/tendermint/proto/tendermint/crypto"
	dbm "github.com/tendermint/tm-db"
	"github.com/ugorji/go/codec"
)

const (
	descriptorsBucket = "k_descriptors"
	documentsBucket   = "k_documents"
	authoritiesBucket = "k_authorities"
)

var (
	defaultLayers           = 3
	defaultMinNodesPerLayer = 2
	jsonHandle              *codec.JsonHandle
)

func init() {
	jsonHandle = new(codec.JsonHandle)
	jsonHandle.Canonical = true
	jsonHandle.IntegerAsString = 'A'
	jsonHandle.MapKeyAsString = true
}

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
	blockHeight  uint64
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

func bytesToAddress(pk [eddsa.PublicKeySize]byte) string {
	p := make([]byte, eddsa.PublicKeySize)
	copy(p, pk[:])
	v := abcitypes.UpdateValidator(p, 0, "")
	pubkey, err := cryptoenc.PubKeyFromProto(v.PubKey)
	if err != nil {
		return ""
	}
	return string(pubkey.Address())
}

func NewKatzenmintState(db dbm.DB) *KatzenmintState {
	// TODO: should load the current state from database
	tree, err := iavl.NewMutableTree(db, 100)
	if err != nil {
		panic(fmt.Errorf("error creating iavl tree"))
	}
	return &KatzenmintState{
		tree:             tree,
		layers:           defaultLayers,
		minNodesPerLayer: defaultMinNodesPerLayer,
		currentEpoch:     1,                       // TODO: load
		genesisEpoch:     1,                       // TODO: load
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

func (state *KatzenmintState) Commit() {
	state.Lock()
	defer state.Unlock()
	if len(state.deferCommit) > 0 {
		for _, def := range state.deferCommit {
			def()
		}
		state.deferCommit = make([]func(), 0)
	}
	state.blockHeight++
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
}

func (state *KatzenmintState) newDocumentRequired() bool {
	// TODO: determine when to finish the current epoch
	return false
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
		return false
	}
	return false
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

func (state *KatzenmintState) storageKey(keyPrefix []byte, identifier string, version uint64) (key []byte) {
	key = make([]byte, len(keyPrefix)+len(identifier)+8)
	copy(key, keyPrefix)
	copy(key[len(keyPrefix):], []byte(identifier))
	verInt := new(big.Int)
	verInt.SetUint64(version)
	copy(key[len(keyPrefix)+len(identifier):], verInt.Bytes())
	return
}

func (state *KatzenmintState) updateMixDescriptor(rawDesc []byte, desc *pki.MixDescriptor, epoch uint64) (err error) {
	state.Lock()
	defer state.Unlock()

	// Note: Caller ensures that the epoch is the current epoch +- 1.
	pk := desc.IdentityKey.ByteArray()

	if epoch < state.blockHeight {
		return fmt.Errorf("state: epoch %v is less than current block height", epoch)
	}

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
	key := state.storageKey([]byte(descriptorsBucket), desc.IdentityKey.String(), epoch)
	if err := state.Set([]byte(key), rawDesc); err != nil {
		return err
	}

	// Store the raw descriptor and the parsed struct.
	state.deferCommit = append(state.deferCommit, func() {
		d := new(descriptor)
		d.desc = desc
		d.raw = rawDesc
		m[pk] = d
	})

	id := hex.EncodeToString(desc.IdentityKey.Bytes())
	fmt.Printf("Node %s: Successfully submitted descriptor for epoch %v.", id, epoch)
	return
}

func (state *KatzenmintState) updateDocument(rawDoc []byte, doc *pki.Document, epoch uint64) (err error) {
	state.Lock()
	defer state.Unlock()

	// Note: Caller ensures that the epoch is the current epoch +- 1.
	// pk := doc.IdentityKey.ByteArray()
	if epoch < state.blockHeight {
		return fmt.Errorf("state: epoch %v is less than current block height", epoch)
	}

	// Get the public key -> document map for the epoch.
	m, ok := state.documents[epoch]
	if ok {
		if !bytes.Equal(m.raw, rawDoc) {
			return fmt.Errorf("state: Conflicting document for epoch %v", epoch)
		}
		// Redundant uploads that don't change are harmless.
		return nil
	}

	e := new(big.Int)
	e.SetUint64(epoch)

	// Persist the raw descriptor to disk.
	key := state.storageKey([]byte(documentsBucket), e.String(), epoch)
	if err := state.Set([]byte(key), rawDoc); err != nil {
		return err
	}

	// Store the raw descriptor and the parsed struct.
	state.deferCommit = append(state.deferCommit, func() {
		d := new(document)
		d.doc = doc
		d.raw = rawDoc
		state.documents[epoch] = d
	})

	epochBytes := make([]byte, 8)
	binary.PutUvarint(epochBytes, epoch)
	state.tree.Set(epochBytes, rawDoc)

	fmt.Printf("Node: Successfully submitted document for epoch %v.", epoch)
	return
}

func (state *KatzenmintState) VerifyAndParseAuthority(payload []byte) (*Authority, error) {
	authority := new(Authority)
	dec := codec.NewDecoderBytes(payload, jsonHandle)
	if err := dec.Decode(authority); err != nil {
		return nil, err
	}
	// TODO: check authority
	if _, ok := state.validators[bytesToAddress(authority.IdentityKey.ByteArray())]; ok {
		return nil, fmt.Errorf("authority had been added")
	}
	return authority, nil
}

func (state *KatzenmintState) updateAuthority(rawAuth []byte, v abcitypes.ValidatorUpdate) error {
	pubkey, err := cryptoenc.PubKeyFromProto(v.PubKey)
	if err != nil {
		return fmt.Errorf("can't decode public key: %w", err)
	}
	key := state.storageKey([]byte(authoritiesBucket), string(pubkey.Bytes()), 0)

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

func (state *KatzenmintState) documentForEpoch(epoch uint64) ([]byte, error) {
	// TODO: postpone the document for some blocks?
	// var postponDeadline = 10

	state.RLock()
	defer state.RUnlock()

	// If we have a serialized document, return it.
	if d, ok := state.documents[epoch]; ok {
		if d.raw != nil {
			return d.raw, nil
		}
		return nil, fmt.Errorf("nil document for epoch %d", epoch)
	}

	// NOTREACHED
	return nil, nil
}
