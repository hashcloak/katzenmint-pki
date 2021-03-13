package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/dgraph-io/badger"
	// "github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/pki"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
	// "github.com/tendermint/tendermint/libs/log"
	pc "github.com/tendermint/tendermint/proto/tendermint/crypto"
)

const (
	descriptorsBucket = "k_descriptors"
	documentsBucket   = "k_documents"
	authoritiesBucket = "k_documents"
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
	blockHeight uint64

	db *badger.DB

	authorizedMixes       map[[eddsa.PublicKeySize]byte]bool
	authorizedAuthorities map[[eddsa.PublicKeySize]byte]bool
	// authorityLinkKeys     map[[eddsa.PublicKeySize]byte]*ecdh.PublicKey

	documents   map[uint64]*document
	descriptors map[uint64]map[[eddsa.PublicKeySize]byte]*descriptor

	// validator set
	validators         map[[eddsa.PublicKeySize]byte]string
	ValUpdates         []abcitypes.ValidatorUpdate
	valAddrToPubKeyMap map[string]pc.PublicKey

	// keep this for panic error?
	// fatalErrCh chan error

	// whether data was changed
	dirty            bool
	transactionBatch *badger.Txn
}

func NewKatzenmintState(db *badger.DB) *KatzenmintState {
	// should load the current state from database
	return &KatzenmintState{
		db:                    db,
		authorizedMixes:       make(map[[eddsa.PublicKeySize]byte]bool),
		authorizedAuthorities: make(map[[eddsa.PublicKeySize]byte]bool),
		documents:             make(map[uint64]*document),
		descriptors:           make(map[uint64]map[[eddsa.PublicKeySize]byte]*descriptor),
		validators:            make(map[[eddsa.PublicKeySize]byte]string),
		ValUpdates:            make([]abcitypes.ValidatorUpdate, 1),
		valAddrToPubKeyMap:    make(map[string]pc.PublicKey),
	}
}

func (state *KatzenmintState) BeginBlock() {
	state.Lock()
	defer state.Unlock()
	// whether the transaction was started
	if state.transactionBatch == nil {
		state.transactionBatch = state.NewTransaction(true)
	}
	state.ValUpdates = make([]abcitypes.ValidatorUpdate, 0)
}

// TODO: put the transactions into block
func (state *KatzenmintState) Commit() {
	state.Lock()
	defer state.Unlock()
	// whether the data was changed
	if state.dirty {
		_ = state.transactionBatch.Commit()
		state.transactionBatch = nil
	}
	state.blockHeight++
}

func (state *KatzenmintState) isAuthorized(address string) bool {
	if _, ok := state.valAddrToPubKeyMap[address]; ok {
		return true
	}
	return false
}

func (state *KatzenmintState) GetAuthorized(address string) (pc.PublicKey, bool) {
	pubkey, ok := state.valAddrToPubKeyMap[address]
	return pubkey, ok
}

func (state *KatzenmintState) isDescriptorAuthorized(desc *pki.MixDescriptor) bool {
	pk := desc.IdentityKey.ByteArray()

	switch desc.Layer {
	case 0:
		return state.authorizedMixes[pk]
	case pki.LayerProvider:
		// check authorities
		_, ok := state.validators[pk]
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

// NewTransaction
func (state *KatzenmintState) NewTransaction(update bool) *badger.Txn {
	return state.db.NewTransaction(update)
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
	if err := state.transactionBatch.Set([]byte(key), rawDesc); err != nil {
		// Persistence failures are FATAL.
		// state.fatalErrCh <- err
		return err
	}
	state.dirty = true

	// Store the raw descriptor and the parsed struct.
	d := new(descriptor)
	d.desc = desc
	d.raw = rawDesc
	m[pk] = d

	id := hex.EncodeToString(desc.IdentityKey.Bytes())
	fmt.Printf("Node %s: Successfully submitted descriptor for epoch %v.", id, epoch)
	// s.onUpdate()
	return
}

func (state *KatzenmintState) updateDocument(rawDoc []byte, doc *pki.Document, epoch uint64) (err error) {
	state.Lock()
	defer state.Unlock()

	// Note: Caller ensures that the epoch is the current epoch +- 1.
	// pk := doc.IdentityKey.ByteArray()

	// Get the public key -> document map for the epoch.
	m, ok := state.documents[epoch]
	if !ok {
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
	if err := state.transactionBatch.Set([]byte(key), rawDoc); err != nil {
		// Persistence failures are FATAL.
		// state.fatalErrCh <- err
		return err
	}
	state.dirty = true

	// Store the raw descriptor and the parsed struct.
	d := new(document)
	d.doc = doc
	d.raw = rawDoc
	state.documents[epoch] = d

	fmt.Printf("Node: Successfully submitted document for epoch %v.", epoch)
	return
}

func (state *KatzenmintState) VerifyAndParseAuthority(payload []byte) (*Authority, error) {
	// Parse the payload.
	authority := new(Authority)
	err := json.Unmarshal(payload, authority)
	if err != nil {
		return nil, err
	}
	// TODO: check authority
	return authority, nil
}

func (state *KatzenmintState) updateAuthority(rawAuth []byte, v abcitypes.ValidatorUpdate) error {
	pubkey, err := cryptoenc.PubKeyFromProto(v.PubKey)
	if err != nil {
		return fmt.Errorf("can't decode public key: %w", err)
	}
	key := []byte("val:" + string(pubkey.Bytes()))

	if v.Power == 0 {
		// remove validator
		auth, err := state.transactionBatch.Get(key)
		if err != nil {
			return err
		}
		if auth != nil {
			return fmt.Errorf("Cannot remove non-existent validator %s", pubkey.Address())
		}
		if err = state.transactionBatch.Delete(key); err != nil {
			return err
		}
		state.dirty = true
		delete(state.valAddrToPubKeyMap, string(pubkey.Address()))
	} else {
		// add or update validator
		value := bytes.NewBuffer(make([]byte, 0))
		if err := abcitypes.WriteMessage(&v, value); err != nil {
			return fmt.Errorf("error encoding validator: %v", err)
		}
		if err = state.transactionBatch.Set(key, value.Bytes()); err != nil {
			// Persistence failures are FATAL.
			// state.fatalErrCh <- err
			return err
		}
		state.dirty = true
		if rawAuth != nil {
			// save payload into database
			key := state.storageKey([]byte(authoritiesBucket), v.PubKey.String(), 0)
			if err := state.transactionBatch.Set([]byte(key), rawAuth); err != nil {
				// Persistence failures are FATAL.
				// state.fatalErrCh <- err
				return err
			}
		}
		state.valAddrToPubKeyMap[string(pubkey.Address())] = v.PubKey
	}

	state.ValUpdates = append(state.ValUpdates, v)

	return nil
}

func (state *KatzenmintState) documentForEpoch(epoch uint64) ([]byte, error) {
	// var generationDeadline = 10

	state.RLock()
	defer state.RUnlock()

	// If we have a serialized document, return it.
	if d, ok := state.documents[epoch]; ok {
		if d.raw != nil {
			return d.raw, nil
		}
		return nil, fmt.Errorf("nil document for epoch %d", epoch)
	}

	// Otherwise, return an error based on the time.
	// now, elapsed, _ := epochtime.Now()
	// switch epoch {
	// case now:
	// 	// Check to see if we are doing a bootstrap, and it's possible that
	// 	// we may decide to publish a document at some point ignoring the
	// 	// standard schedule.
	// 	if now == s.bootstrapEpoch || now - 1 == s.bootstrapEpoch {
	// 		return nil, errNotYet
	// 	}

	// 	// We missed the deadline to publish a descriptor for the current
	// 	// epoch, so we will never be able to service this request.
	// 	s.log.Errorf("No document for current epoch %v generated and never will be", now)
	// 	return nil, errGone
	// case now + 1:
	// 	if now == s.bootstrapEpoch {
	// 		return nil, errNotYet
	// 	}
	// 	// If it's past the time by which we should have generated a document
	// 	// then we will never be able to service this.
	// 	if elapsed > generationDeadline {
	// 		s.log.Errorf("No document for next epoch %v and it's already past 7/8 of previous epoch", now+1)
	// 		return nil, errGone
	// 	}
	// 	return nil, errNotYet
	// default:
	// 	if epoch < now {
	// 		// Requested epoch is in the past, and it's not in the cache.
	// 		// We will never be able to satisfy this request.
	// 		s.log.Errorf("No document for epoch %v, because we are already in %v", epoch, now)
	// 		return nil, errGone
	// 	}
	// 	return nil, fmt.Errorf("state: Request for invalid epoch: %v", epoch)
	// }

	// NOTREACHED
	return nil, nil
}
