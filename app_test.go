package katzenmint

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/dgraph-io/badger"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/rpc/client/mock"
	types "github.com/tendermint/tendermint/types"
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
			db, err := badger.Open(badger.DefaultOptions(node.DBPath))
			if err != nil {
				t.Fatalf("Failed to open badger db: %v", err)
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
			info, err := m.ABCIInfo(context.Background())
			require.Nil(err)
			assert.Equal(``, info.Response.GetData())

			// create authority
			authority := new(Authority)
			authority.Auth = "katzenmint"
			authority.Power = 1
			privKey, err := eddsa.NewKeypair(rand.Reader)
			require.NoError(err, "eddsa.NewKeypair()")
			authority.IdentityKey = privKey.PublicKey()
			linkPriv, err := ecdh.NewKeypair(rand.Reader)
			require.NoError(err, "ecdh.NewKeypair()")
			authority.LinkKey = linkPriv.PublicKey()
			rawAuth, err := json.Marshal(authority)
			if err != nil {
				t.Fatalf("Failed to marshal authority: %+v\n", err)
			}

			// add authority
			tx := new(transaction)
			tx.Version = fmt.Sprintf("%d", ProtocolVersion)
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
			encTx, _ := json.Marshal(tx)
			m.App.BeginBlock(abcitypes.RequestBeginBlock{})
			res, err := m.BroadcastTxCommit(context.Background(), types.Tx(encTx))
			require.Nil(err)
			assert.True(res.CheckTx.IsOK())
			require.NotNil(res.DeliverTx)
			assert.True(res.DeliverTx.IsOK())

			m.App.Commit()

			key := app.state.storageKey([]byte(authoritiesBucket), string(authority.IdentityKey.Bytes()), 0)
			rtx := app.state.NewTransaction(false)
			_, err = rtx.Get(key)
			if err != nil {
				t.Fatalf("Failed to get authority from database: %+v\n", err)
			}
			if len(app.state.validatorUpdates) <= 0 {
				t.Fatal("Failed to update authority\n")
			}
		}
	}
}
