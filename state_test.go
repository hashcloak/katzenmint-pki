package katzenmint

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/hashcloak/katzenmint-pki/s11n"
	"github.com/hashcloak/katzenmint-pki/testutil"
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

const testEpoch = genesisEpoch

var ()

func TestUpdateDescriptor(t *testing.T) {
	require := require.New(t)

	// create katzenmint state
	db := dbm.NewMemDB()
	defer db.Close()
	state := NewKatzenmintState(db)

	// create test descriptor
	desc, rawDesc := testutil.CreateTestDescriptor(require, 1, pki.LayerProvider, testEpoch)

	// update mix descriptor
	state.BeginBlock()
	err := state.updateMixDescriptor(rawDesc, desc, testEpoch)
	if err != nil {
		t.Fatalf("Failed to update mix descriptor: %+v\n", err)
	}
	_, err = state.Commit()
	if err != nil {
		t.Fatalf("Failed to commit: %v\n", err)
	}

	// test the data exists in memory
	pk := desc.IdentityKey.ByteArray()
	if m, ok := state.descriptors[testEpoch]; !ok {
		t.Fatal("Failed to update mix descriptor\n")
	} else {
		// should we compare descriptors?
		if _, ok := m[pk]; !ok {
			t.Fatal("Failed to update mix descriptor\n")
		}
	}

	// test the data exists in database
	key := storageKey(descriptorsBucket, desc.IdentityKey.Bytes(), testEpoch)
	_, err = state.Get(key)
	if err != nil {
		t.Fatalf("Failed to get mix descriptor from database: %+v\n", err)
	}
}

func TestUpdateDocument(t *testing.T) {
	require := require.New(t)

	// create katzenmint state
	db := dbm.NewMemDB()
	defer db.Close()
	state := NewKatzenmintState(db)

	// create, validate and deserialize document.
	_, sDoc := testutil.CreateTestDocument(require, testEpoch)
	dDoc, err := s11n.VerifyAndParseDocument([]byte(sDoc))
	if err != nil {
		t.Fatalf("Failed to VerifyAndParseDocument document: %+v\n", err)
	}
	rawDoc := make([]byte, 10)
	enc := codec.NewEncoderBytes(&rawDoc, jsonHandle)
	if err := enc.Encode(dDoc); err != nil {
		t.Fatalf("Failed to marshal pki document: %+v\n", err)
	}

	// update document
	state.BeginBlock()
	err = state.updateDocument(rawDoc, dDoc, testEpoch)
	if err != nil {
		t.Fatalf("Failed to update pki document: %+v\n", err)
	}
	_, err = state.Commit()
	if err != nil {
		t.Fatalf("Failed to commit: %v\n", err)
	}

	// test the data exists in memory
	if _, ok := state.documents[testEpoch]; !ok {
		t.Fatal("Failed to update pki document\n")
	}

	// test the data exists in database
	e := make([]byte, 8)
	binary.PutUvarint(e, testEpoch)
	key := storageKey(documentsBucket, e, testEpoch)
	_, err = state.Get(key)
	if err != nil {
		t.Fatalf("Failed to get pki document from database: %+v\n", err)
	}
}

func TestUpdateAuthority(t *testing.T) {
	require := require.New(t)

	// create katzenmint state
	db := dbm.NewMemDB()
	defer db.Close()
	state := NewKatzenmintState(db)

	// create authority
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

	// update authority
	state.BeginBlock()
	err = state.updateAuthority(rawAuth, abcitypes.UpdateValidator(authority.IdentityKey.Bytes(), authority.Power, ""))
	if err != nil {
		fmt.Printf("Failed to update authority: %+v\n", err)
		return
	}
	_, err = state.Commit()
	if err != nil {
		t.Fatalf("Failed to commit: %v\n", err)
	}

	// test the data exists in database
	key := storageKey(authoritiesBucket, authority.IdentityKey.Bytes(), 0)
	_, err = state.Get(key)
	if err != nil {
		t.Fatalf("Failed to get authority from database: %+v\n", err)
	}
	if len(state.validatorUpdates) != 1 {
		t.Fatal("Failed to update authority\n")
	}
}

func TestDocumentGenerationUponCommit(t *testing.T) {
	require := require.New(t)

	// create katzenmint state
	db := dbm.NewMemDB()
	defer db.Close()
	state := NewKatzenmintState(db)
	epoch := state.currentEpoch
	e := make([]byte, 8)
	binary.PutUvarint(e, epoch)
	key := storageKey(documentsBucket, e, epoch)

	// create descriptorosts of providers
	providers := make([]descriptor, 0)
	for i := 0; i < state.minNodesPerLayer; i++ {
		desc, rawDesc := testutil.CreateTestDescriptor(require, i, pki.LayerProvider, epoch)
		providers = append(providers, descriptor{desc: desc, raw: rawDesc})
	}

	// create descriptors of mixs
	mixs := make([]descriptor, 0)
	for layer := 0; layer < state.layers; layer++ {
		for i := 0; i < state.minNodesPerLayer; i++ {
			desc, rawDesc := testutil.CreateTestDescriptor(require, i, 0, epoch)
			mixs = append(mixs, descriptor{desc: desc, raw: rawDesc})
		}
	}

	// update part of the descriptors
	state.BeginBlock()
	for _, p := range providers {
		err := state.updateMixDescriptor(p.raw, p.desc, epoch)
		if err != nil {
			t.Fatalf("Failed to update provider descriptor: %+v\n", err)
		}
	}
	for i, m := range mixs {
		if i == 0 {
			// skip one of the mix descriptors
			continue
		}
		err := state.updateMixDescriptor(m.raw, m.desc, epoch)
		if err != nil {
			t.Fatalf("Failed to update mix descriptor: %+v\n", err)
		}
	}
	_, err := state.Commit()
	if err != nil {
		t.Fatalf("Failed to commit: %v\n", err)
	}

	// proceed with enough block commits to enter the next epoch
	for i := 0; i < int(epochInterval)-1; i++ {
		state.BeginBlock()
		_, err = state.Commit()
		if err != nil {
			t.Fatalf("Failed to commit: %v\n", err)
		}
	}
	state.BeginBlock()
	_, err = state.Commit()
	if err == nil {
		t.Fatal("Commit should fail because threshold of document creation is not achieved")
	}

	// test the non-existence of the document
	_, ok := state.documents[epoch]
	_, err = state.Get(key)
	if ok || err == nil {
		t.Fatalf("The pki document should not be generated at this moment because there is not enough mix descriptors\n")
	}

	// update the remaining descriptors up to the required threshold
	state.BeginBlock()
	err = state.updateMixDescriptor(mixs[0].raw, mixs[0].desc, epoch)
	if err != nil {
		t.Fatalf("Failed to update mix descriptor: %+v\n", err)
	}
	_, err = state.Commit()
	if err != nil {
		t.Fatalf("Failed to commit: %v\n", err)
	}

	// test the existence of the document
	_, ok = state.documents[epoch]
	_, err = state.Get(key)
	if !ok || err != nil {
		t.Fatalf("The pki document should be generated automatically\n")
	}
}
