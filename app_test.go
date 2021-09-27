package katzenmint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"net/url"
	"testing"

	"github.com/cosmos/iavl"
	"github.com/hashcloak/katzenmint-pki/testutil"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto/merkle"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/rpc/client/mock"
	dbm "github.com/tendermint/tm-db"
	"github.com/ugorji/go/codec"
)

func newDiscardLogger() (logger log.Logger) {
	logger = log.NewTMLogger(log.NewSyncWriter(ioutil.Discard))
	return
}

func TestAddAuthority(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	// setup application
	db := dbm.NewMemDB()
	defer db.Close()
	logger := newDiscardLogger()
	app := NewKatzenmintApplication(kConfig, db, logger)
	m := mock.ABCIApp{
		App: app,
	}

	// create authority
	authority := new(Authority)
	authority.Auth = "katzenmint"
	authority.Power = 1
	privKey, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err, "eddsa.NewKeypair()")
	authority.IdentityKey = privKey.PublicKey()
	/* linkPriv, err := ecdh.NewKeypair(rand.Reader) */
	linkPriv := privKey.ToECDH()
	require.NoError(err, "ecdh.NewKeypair()")
	authority.LinkKey = linkPriv.PublicKey()
	rawAuth := make([]byte, 128)
	enc := codec.NewEncoderBytes(&rawAuth, jsonHandle)
	if err := enc.Encode(authority); err != nil {
		t.Fatalf("Failed to marshal authority: %+v\n", err)
	}

	// form transaction
	tx := new(Transaction)
	tx.Version = ProtocolVersion
	tx.Epoch = 1
	tx.Command = AddNewAuthority
	tx.Payload = string(rawAuth)
	pubKey := authority.IdentityKey.Bytes()
	tx.PublicKey = EncodeHex(pubKey[:])
	msgHash := tx.SerializeHash()
	sig := privKey.Sign(msgHash[:])
	tx.Signature = EncodeHex(sig[:])
	if !tx.IsVerified() {
		t.Fatalf("Transaction is not verified: %+v\n", tx)
	}
	encTx := make([]byte, 128)
	enc2 := codec.NewEncoderBytes(&encTx, jsonHandle)
	if err := enc2.Encode(tx); err != nil {
		t.Fatalf("Failed to marshal transaction: %+v\n", err)
	}

	// post transaction to app
	m.App.BeginBlock(abcitypes.RequestBeginBlock{})
	res, err := m.BroadcastTxCommit(context.Background(), encTx)
	require.Nil(err)
	assert.True(res.CheckTx.IsOK())
	require.NotNil(res.DeliverTx)
	assert.True(res.DeliverTx.IsOK())

	// commit once
	m.App.Commit()

	// make checks
	validator := abcitypes.UpdateValidator(authority.IdentityKey.Bytes(), authority.Power, "")
	protoPubKey, err := validator.PubKey.Marshal()
	if err != nil {
		t.Fatalf("Failed to encode public with protobuf: %v\n", err)
	}
	key := storageKey(authoritiesBucket, protoPubKey, 0)
	_, err = app.state.Get(key)
	if err != nil {
		t.Fatalf("Failed to get authority from database: %+v\n", err)
	}
	if len(app.state.validatorUpdates) <= 0 {
		t.Fatal("Failed to update authority\n")
	}
}

func TestPostDescriptorAndCommit(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	// setup application
	db := dbm.NewMemDB()
	defer db.Close()
	logger := newDiscardLogger()
	app := NewKatzenmintApplication(kConfig, db, logger)
	m := mock.ABCIApp{
		App: app,
	}

	// fetch current epoch
	appinfo, err := m.ABCIInfo(context.Background())
	require.Nil(err)
	epochBytes := DecodeHex(appinfo.Response.Data)
	epoch, err := binary.ReadUvarint(bytes.NewReader(epochBytes))
	require.Nil(err)

	// create descriptors of providers and mixs
	descriptors := make([][]byte, 0)
	for i := 0; i < app.state.minNodesPerLayer; i++ {
		_, rawDesc, _ := testutil.CreateTestDescriptor(require, i, pki.LayerProvider, epoch)
		descriptors = append(descriptors, rawDesc)
	}
	for layer := 0; layer < app.state.layers; layer++ {
		for i := 0; i < app.state.minNodesPerLayer; i++ {
			_, rawDesc, _ := testutil.CreateTestDescriptor(require, i, 0, epoch)
			descriptors = append(descriptors, rawDesc)
		}
	}

	// create transaction for each descriptor
	transactions := make([][]byte, 0)
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err, "GenerateKey()")
	for _, rawDesc := range descriptors {
		rawTx := Transaction{
			Version: ProtocolVersion,
			Epoch:   epoch,
			Command: PublishMixDescriptor,
			Payload: EncodeHex(rawDesc),
		}
		rawTx.AppendSignature(privKey)
		packedTx, err := json.Marshal(rawTx)
		require.NoError(err, "Marshal raw transaction")
		transactions = append(transactions, packedTx)
	}

	// post descriptor transactions to app
	m.App.BeginBlock(abcitypes.RequestBeginBlock{})
	for _, tx := range transactions {
		res, err := m.BroadcastTxCommit(context.Background(), tx)
		require.Nil(err)
		assert.True(res.CheckTx.IsOK(), res.CheckTx.Log)
		require.NotNil(res.DeliverTx)
		assert.True(res.DeliverTx.IsOK(), res.DeliverTx.Log)
	}

	// commit through the epoch
	for i := int64(0); i <= epochInterval; i++ {
		m.App.Commit()
	}

	// test the doc is formed and exists in state
	loaded, _, err := app.state.documentForEpoch(epoch, app.state.blockHeight)
	require.Nil(err, "Failed to get pki document from state: %+v\n", err)
	require.NotNil(loaded, "Failed to get pki document from state: wrong key")
	// test against the expected doc?
	/* require.Equal(sDoc, loaded, "App state contains an erroneous pki document") */

	// prepare verification metadata
	appinfo, err = m.ABCIInfo(context.Background())
	require.Nil(err)
	apphash := appinfo.Response.LastBlockAppHash
	e := make([]byte, 8)
	binary.PutUvarint(e, epoch)
	key := storageKey(documentsBucket, e, epoch)
	path := "/" + url.PathEscape(string(key))

	m.App.Commit()

	// make a query for the doc
	var data []byte
	query := Query{
		Version: ProtocolVersion,
		Epoch:   epoch,
		Command: GetConsensus,
		Payload: "",
	}
	err = codec.NewEncoderBytes(&data, jsonHandle).Encode(query)
	require.Nil(err)

	rsp, err := m.ABCIQuery(context.Background(), "", data)
	require.Nil(err)
	require.True(rsp.Response.IsOK(), rsp.Response.Log)
	require.Equal(loaded, rsp.Response.Value, "App responses with an erroneous pki document")

	// verify query proof
	verifier := merkle.NewProofRuntime()
	verifier.RegisterOpDecoder(iavl.ProofOpIAVLValue, iavl.ValueOpDecoder)
	err = verifier.VerifyValue(rsp.Response.ProofOps, apphash, path, rsp.Response.Value)
	require.Nil(err, "Invalid proof for app responses")
}
