package katzenmint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"net/url"
	"os"
	"testing"

	"github.com/cosmos/iavl"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto/merkle"
	"github.com/tendermint/tendermint/rpc/client/mock"
	dbm "github.com/tendermint/tm-db"
	"github.com/ugorji/go/codec"
)

// Node represents test node
type Node struct {
	// ConfigPath string
	DBPath string
}

var testNodes = []Node{
	{
		DBPath: "./testnode1db",
	}, {
		DBPath: "./testnode2db",
	},
}

// katzenmint integration test
func TestAddAuthority(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	for i, node := range testNodes {
		if i == 0 {
			db, err := dbm.NewDB("katzenmint_db", dbm.BadgerDBBackend, node.DBPath)
			if err != nil {
				t.Fatalf("Failed to open badger db: %v; try running with -tags badgerdb", err)
			}
			defer func(dbPath string) {
				db.Close()
				os.RemoveAll(dbPath)
			}(node.DBPath)

			app := NewKatzenmintApplication(db)
			m := mock.ABCIApp{
				App: app,
			}

			// get some info
			_, err = m.ABCIInfo(context.Background())
			require.Nil(err)

			// create authority
			authority := new(Authority)
			authority.Auth = "katzenmint"
			authority.Power = 1
			privKey, err := eddsa.NewKeypair(rand.Reader)
			require.NoError(err, "eddsa.NewKeypair()")
			authority.IdentityKey = privKey.PublicKey()
			// linkPriv, err := ecdh.NewKeypair(rand.Reader)
			linkPriv := privKey.ToECDH()
			require.NoError(err, "ecdh.NewKeypair()")
			authority.LinkKey = linkPriv.PublicKey()

			rawAuth := make([]byte, 128)
			enc := codec.NewEncoderBytes(&rawAuth, jsonHandle)
			if err := enc.Encode(authority); err != nil {
				t.Fatalf("Failed to marshal authority: %+v\n", err)
			}

			// add authority
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

			m.App.BeginBlock(abcitypes.RequestBeginBlock{})
			res, err := m.BroadcastTxCommit(context.Background(), encTx)
			require.Nil(err)
			assert.True(res.CheckTx.IsOK())
			require.NotNil(res.DeliverTx)
			assert.True(res.DeliverTx.IsOK())

			m.App.Commit()

			key := storageKey(authoritiesBucket, authority.IdentityKey.Bytes(), 0)
			_, err = app.state.Get(key)
			if err != nil {
				t.Fatalf("Failed to get authority from database: %+v\n", err)
			}
			if len(app.state.validatorUpdates) <= 0 {
				t.Fatal("Failed to update authority\n")
			}
		}
	}
}

func TestPostDocument(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	// setup application
	db := dbm.NewMemDB()
	defer db.Close()
	app := NewKatzenmintApplication(db)
	m := mock.ABCIApp{
		App: app,
	}

	// fetch current epoch
	appinfo, err := m.ABCIInfo(context.Background())
	require.Nil(err)
	epochBytes := DecodeHex(appinfo.Response.Data)
	epoch, err := binary.ReadUvarint(bytes.NewReader(epochBytes))
	require.Nil(err)

	// Create transaction
	_, sDoc := CreateTestDocument(require, epoch)
	rawTx := Transaction{
		Version: ProtocolVersion,
		Epoch:   epoch,
		Command: AddConsensusDocument,
		Payload: string(sDoc),
	}
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err, "GenerateKey()")
	rawTx.AppendSignature(privKey)
	tx, err := json.Marshal(rawTx)
	require.NoError(err, "Marshal raw transaction")

	// run app
	m.App.BeginBlock(abcitypes.RequestBeginBlock{})
	res, err := m.BroadcastTxCommit(context.Background(), tx)
	require.Nil(err)
	assert.True(res.CheckTx.IsOK())
	require.NotNil(res.DeliverTx)
	assert.True(res.DeliverTx.IsOK())
	m.App.Commit()

	// test the data exists in state
	loaded, _, err := app.state.documentForEpoch(epoch)
	require.Nil(err, "Failed to get pki document from state: %+v\n", err)
	require.NotNil(loaded, "Failed to get pki document from state: wrong key")
	require.Equal(sDoc, loaded, "App state contains an erroneous pki document")

	// make a query
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
	require.Equal(sDoc, rsp.Response.Value, "App responses with an erroneous pki document")

	// prepare verification metadata
	appinfo, err = m.ABCIInfo(context.Background())
	require.Nil(err)
	apphash := appinfo.Response.LastBlockAppHash
	e := make([]byte, 8)
	binary.PutUvarint(e, epoch)
	key := storageKey(documentsBucket, e, epoch)
	path := "/" + url.PathEscape(string(key))

	// verify query proof
	verifier := merkle.NewProofRuntime()
	verifier.RegisterOpDecoder(iavl.ProofOpIAVLValue, iavl.ValueOpDecoder)
	err = verifier.VerifyValue(rsp.Response.ProofOps, apphash, path, rsp.Response.Value)
	require.Nil(err, "Invalid proof for app responses")
}
