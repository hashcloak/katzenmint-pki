package katzenmint

import (
	"fmt"
	"math/big"
	"os"
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

const (
	testEpoch            = 1
	testDescriptorDBPath = "./testdescdb"
	testDocumentDBPath   = "./testdocdb"
	testAuthorityDBPath  = "./testauthdb"
)

// create test state
func createState(db dbm.DB) (state *KatzenmintState) {
	state = NewKatzenmintState(db)
	return
}

// clean test data
func cleanTest(db dbm.DB, dbPath string) {
	db.Close()
	err := os.RemoveAll(dbPath)
	if err != nil {
		fmt.Println(err)
	}
}

// create test descriptor
func createDescriptor(require *require.Assertions, idx int, layer int) (*pki.MixDescriptor, []byte) {
	desc := new(pki.MixDescriptor)
	desc.Name = fmt.Sprintf("katzenmint%d.example.net", idx)
	desc.Addresses = map[pki.Transport][]string{
		pki.TransportTCPv4: []string{fmt.Sprintf("192.0.2.%d:4242", idx)},
		pki.TransportTCPv6: []string{"[2001:DB8::1]:8901"},
		// pki.Transport("torv2"): []string{"thisisanoldonion.onion:2323"},
		// pki.TransportTCP: []string{"example.com:4242"},
	}
	desc.Layer = uint8(layer)
	desc.LoadWeight = 23
	identityPriv, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err, "eddsa.NewKeypair()")
	desc.IdentityKey = identityPriv.PublicKey()
	linkPriv, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "ecdh.NewKeypair()")
	desc.LinkKey = linkPriv.PublicKey()
	desc.MixKeys = make(map[uint64]*ecdh.PublicKey)
	for e := testEpoch; e < testEpoch+3; e++ {
		mPriv, err := ecdh.NewKeypair(rand.Reader)
		require.NoError(err, "[%d]: ecdh.NewKeypair()", e)
		desc.MixKeys[uint64(e)] = mPriv.PublicKey()
	}
	if layer == pki.LayerProvider {
		desc.Kaetzchen = make(map[string]map[string]interface{})
		desc.Kaetzchen["miau"] = map[string]interface{}{
			"endpoint":  "+miau",
			"miauCount": idx,
		}
	}
	err = s11n.IsDescriptorWellFormed(desc, testEpoch)
	require.NoError(err, "IsDescriptorWellFormed(good)")

	// Sign the descriptor.
	signed, err := s11n.SignDescriptor(identityPriv, desc)
	require.NoError(err, "SignDescriptor()")
	return desc, signed
}

func TestUpdateDescriptor(t *testing.T) {
	require := require.New(t)
	desc, _ := createDescriptor(require, 1, pki.LayerProvider)
	rawDesc := make([]byte, 10)
	enc := codec.NewEncoderBytes(&rawDesc, jsonHandle)
	if err := enc.Encode(desc); err != nil {
		t.Fatalf("Failed to marshal mix descriptor: %+v\n", err)
	}
	db, err := dbm.NewDB("katzenmint_db", dbm.BadgerDBBackend, testDescriptorDBPath)
	if err != nil {
		t.Fatalf("Failed to open badger db: %v; try running with -tags badgerdb", err)
	}
	defer cleanTest(db, testDescriptorDBPath)
	state := createState(db)
	state.BeginBlock()
	err = state.updateMixDescriptor(rawDesc, desc, testEpoch)
	if err != nil {
		t.Fatalf("Failed to update mix descriptor: %+v\n", err)
	}
	state.Commit()

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
	key := state.storageKey([]byte(descriptorsBucket), desc.IdentityKey.String(), testEpoch)
	_, err = state.Get(key)
	if err != nil {
		t.Fatalf("Failed to get mix descriptor from database: %+v\n", err)
	}
}

func TestUpdateDocument(t *testing.T) {
	// assert := assert.New(t)
	require := require.New(t)

	testSendRate := uint64(3)

	// Generate a Document.
	doc := &s11n.Document{
		Epoch:             testEpoch,
		GenesisEpoch:      testEpoch,
		SendRatePerMinute: testSendRate,
		Topology:          make([][][]byte, 3),
		Mu:                0.42,
		MuMaxDelay:        23,
		LambdaP:           0.69,
		LambdaPMaxDelay:   17,
	}
	idx := 1
	for l := 0; l < 3; l++ {
		for i := 0; i < 5; i++ {
			_, rawDesc := createDescriptor(require, idx, 0)
			doc.Topology[l] = append(doc.Topology[l], rawDesc)
			idx++
		}
	}
	for i := 0; i < 3; i++ {
		_, rawDesc := createDescriptor(require, idx, pki.LayerProvider)
		doc.Providers = append(doc.Providers, rawDesc)
		idx++
	}

	// Serialize
	serialized, err := s11n.SerializeDocument(doc)
	require.NoError(err, "SerializeDocument()")

	// Validate and deserialize.
	ddoc, err := s11n.VerifyAndParseDocument([]byte(serialized))
	if err != nil {
		t.Fatalf("Failed to VerifyAndParseDocument document: %+v\n", err)
	}
	rawDoc := make([]byte, 10)
	enc := codec.NewEncoderBytes(&rawDoc, jsonHandle)
	if err := enc.Encode(ddoc); err != nil {
		t.Fatalf("Failed to marshal pki document: %+v\n", err)
	}
	db, err := dbm.NewDB("katzenmint_db", dbm.BadgerDBBackend, testDocumentDBPath)
	if err != nil {
		t.Fatalf("Failed to open badger db: %v; try running with -tags badgerdb", err)
	}
	defer cleanTest(db, testDocumentDBPath)
	state := createState(db)

	state.BeginBlock()
	err = state.updateDocument(rawDoc, ddoc, testEpoch)
	if err != nil {
		t.Fatalf("Failed to update pki document: %+v\n", err)
	}
	state.Commit()

	if _, ok := state.documents[testEpoch]; !ok {
		t.Fatal("Failed to update pki document\n")
	}
	// test the data exists in db
	e := new(big.Int)
	e.SetUint64(testEpoch)
	key := state.storageKey([]byte(documentsBucket), e.String(), testEpoch)
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
	db, err := dbm.NewDB("katzenmint_db", dbm.BadgerDBBackend, testAuthorityDBPath)
	if err != nil {
		t.Fatalf("Failed to open badger db: %v; try running with -tags badgerdb", err)
	}
	defer cleanTest(db, testAuthorityDBPath)
	state := createState(db)

	state.BeginBlock()
	err = state.updateAuthority(rawAuth, abcitypes.UpdateValidator(authority.IdentityKey.Bytes(), authority.Power, ""))
	if err != nil {
		fmt.Printf("Failed to update authority: %+v\n", err)
		return
	}
	state.Commit()

	key := state.storageKey([]byte(authoritiesBucket), string(authority.IdentityKey.Bytes()), 0)
	_, err = state.Get(key)
	if err != nil {
		t.Fatalf("Failed to get authority from database: %+v\n", err)
	}
	if len(state.validatorUpdates) != 1 {
		t.Fatal("Failed to update authority\n")
	}
}
