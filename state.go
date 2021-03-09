package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	"github.com/dgraph-io/badger"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/pki"
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
	db *badger.DB

	authorizedMixes       map[[eddsa.PublicKeySize]byte]bool
	authorizedProviders   map[[eddsa.PublicKeySize]byte]string
	authorizedAuthorities map[[eddsa.PublicKeySize]byte]bool
	authorityLinkKeys     map[[eddsa.PublicKeySize]byte]*ecdh.PublicKey

	documents   map[uint64]*document
	descriptors map[uint64]map[[eddsa.PublicKeySize]byte]*descriptor
	votes       map[uint64]map[[eddsa.PublicKeySize]byte]*document
}

func NewKatzenmintState(db *badger.DB) *KatzenmintState {
	return &KatzenmintState{
		db: db,
	}
}

func (state *KatzenmintState) isDescriptorAuthorized(desc *pki.MixDescriptor) bool {
	pk := desc.IdentityKey.ByteArray()

	switch desc.Layer {
	case 0:
		return state.authorizedMixes[pk]
	case pki.LayerProvider:
		name, ok := state.authorizedProviders[pk]
		if !ok {
			return false
		}
		return name == desc.Name
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
	tx := state.NewTransaction(true)
	key := state.storageKey([]byte(descriptorsBucket), desc.IdentityKey.String(), epoch)
	if err := tx.Set([]byte(key), rawDesc); err != nil {
		// Persistence failures are FATAL.
		// s.s.fatalErrCh <- err
	}
	_ = tx.Commit()

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
	tx := state.NewTransaction(true)
	key := state.storageKey([]byte(documentsBucket), e.String(), epoch)
	if err := tx.Set([]byte(key), rawDoc); err != nil {
		// Persistence failures are FATAL.
		// s.s.fatalErrCh <- err
	}
	_ = tx.Commit()

	// Store the raw descriptor and the parsed struct.
	d := new(document)
	d.doc = doc
	d.raw = rawDoc
	state.documents[epoch] = d

	fmt.Printf("Node: Successfully submitted document for epoch %v.", epoch)
	return
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
