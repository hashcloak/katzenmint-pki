package main

import (
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

// NewTransaction
func (state *KatzenmintState) NewTransaction(readOnly bool) *badger.Txn {
	return state.db.NewTransaction(readOnly)
}