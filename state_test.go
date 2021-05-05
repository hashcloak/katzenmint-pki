package katzenmint

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/hashcloak/katzenmint-pki/s11n"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	dbm "github.com/tendermint/tm-db"
	"github.com/ugorji/go/codec"

	// "github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testEpoch = 1

func TestUpdateDescriptor(t *testing.T) {
	require := require.New(t)
	desc, _ := CreateTestDescriptor(require, 1, pki.LayerProvider, testEpoch)
	rawDesc := make([]byte, 10)
	enc := codec.NewEncoderBytes(&rawDesc, jsonHandle)
	if err := enc.Encode(desc); err != nil {
		t.Fatalf("Failed to marshal mix descriptor: %+v\n", err)
	}
	db := dbm.NewMemDB()
	defer db.Close()
	state := NewKatzenmintState(db)
	state.BeginBlock()
	err := state.updateMixDescriptor(rawDesc, desc, testEpoch)
	if err != nil {
		t.Fatalf("Failed to update mix descriptor: %+v\n", err)
	}
	_ = state.Commit()

	pk := desc.IdentityKey.ByteArray()
	if m, ok := state.descriptors[testEpoch]; !ok {
		t.Fatal("Failed to update mix descriptor\n")
	} else {
		// should we compare descriptors?
		if _, ok := m[pk]; !ok {
			t.Fatal("Failed to update mix descriptor\n")
		}
	}
	// test the data exists in db
	key := storageKey(descriptorsBucket, desc.IdentityKey.Bytes(), testEpoch)
	_, err = state.Get(key)
	if err != nil {
		t.Fatalf("Failed to get mix descriptor from database: %+v\n", err)
	}
}

func TestUpdateDocument(t *testing.T) {
	// assert := assert.New(t)
	require := require.New(t)

	// Create, validate and deserialize document.
	_, sDoc := CreateTestDocument(require, testEpoch)
	dDoc, err := s11n.VerifyAndParseDocument([]byte(sDoc))
	if err != nil {
		t.Fatalf("Failed to VerifyAndParseDocument document: %+v\n", err)
	}
	rawDoc := make([]byte, 10)
	enc := codec.NewEncoderBytes(&rawDoc, jsonHandle)
	if err := enc.Encode(dDoc); err != nil {
		t.Fatalf("Failed to marshal pki document: %+v\n", err)
	}

	// create katzenmint state
	db := dbm.NewMemDB()
	defer db.Close()
	state := NewKatzenmintState(db)

	// update document to state
	state.BeginBlock()
	err = state.updateDocument(rawDoc, dDoc, testEpoch)
	if err != nil {
		t.Fatalf("Failed to update pki document: %+v\n", err)
	}
	_ = state.Commit()
	if _, ok := state.documents[testEpoch]; !ok {
		t.Fatal("Failed to update pki document\n")
	}

	// test the data exists in state tree
	e := make([]byte, 8)
	binary.PutUvarint(e, testEpoch)
	key := storageKey(documentsBucket, e, testEpoch)
	_, err = state.Get(key)
	if err != nil {
		t.Fatalf("Failed to get pki document from database: %+v\n", err)
	}
}

func TestUpdateAuthority(t *testing.T) {
	// assert := assert.New(t)
	require := require.New(t)
	authority := new(Authority)

	authority.Auth = "katzenmint"
	authority.Power = 1
	k, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err, "eddsa.NewKeypair()")
	authority.IdentityKey = k.PublicKey()
	linkPriv, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "ecdh.NewKeypair()")
	authority.LinkKey = linkPriv.PublicKey()
	rawAuth := make([]byte, 10)
	enc := codec.NewEncoderBytes(&rawAuth, jsonHandle)
	if err := enc.Encode(authority); err != nil {
		t.Fatalf("Failed to marshal authority: %+v\n", err)
	}
	db := dbm.NewMemDB()
	defer db.Close()
	state := NewKatzenmintState(db)

	state.BeginBlock()
	err = state.updateAuthority(rawAuth, abcitypes.UpdateValidator(authority.IdentityKey.Bytes(), authority.Power, ""))
	if err != nil {
		fmt.Printf("Failed to update authority: %+v\n", err)
		return
	}
	_ = state.Commit()

	key := storageKey(authoritiesBucket, authority.IdentityKey.Bytes(), 0)
	_, err = state.Get(key)
	if err != nil {
		t.Fatalf("Failed to get authority from database: %+v\n", err)
	}
	if len(state.validatorUpdates) != 1 {
		t.Fatal("Failed to update authority\n")
	}
}
