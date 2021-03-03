package main

import (
	"crypto/ed25519"
	// "crypto/sha256"
	"encoding/json"
	"fmt"

	// "github.com/ugorji/go/codec"
	"github.com/dgraph-io/badger"
	"github.com/hashcloak/katzenmint-pki/s11n"
	"github.com/katzenpost/core/crypto/cert"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/pki"
	abcitypes "github.com/tendermint/tendermint/abci/types"
)

const (
	descriptorsBucket = "k_decsriptors"
)

var (
	_ abcitypes.Application = (*KatzenmintApplication)(nil)
	// jsonHandle *codec.JsonHandle
)

// TODO: when to discard db transaction
type KatzenmintApplication struct {
	state               *KatzenmintState
	currentBatch        *badger.Txn
	authorizedMixes     map[PublicKeyByte]bool
	authorizedProviders map[PublicKeyByte]string
}

// TODO: check codec json handle
// dec := codec.NewDecoderBytes(rawTx, jsonHandle)
// func init() {
// 	jsonHandle = new(codec.JsonHandle)
// 	jsonHandle.Canonical = true
// 	jsonHandle.IntegerAsString = 'A'
// 	jsonHandle.MapKeyAsString = true
// }

func NewKatzenmintApplication(db *badger.DB) *KatzenmintApplication {
	state := NewKatzenmintState(db)
	return &KatzenmintApplication{
		state: state,
	}
}

func (KatzenmintApplication) Info(req abcitypes.RequestInfo) abcitypes.ResponseInfo {
	return abcitypes.ResponseInfo{}
}

func (KatzenmintApplication) SetOption(req abcitypes.RequestSetOption) abcitypes.ResponseSetOption {
	return abcitypes.ResponseSetOption{}
}

func (app *KatzenmintApplication) isTxValid(rawTx []byte) (code uint32, tx *transaction) {
	tx = new(transaction)
	if err := json.Unmarshal(rawTx, tx); err != nil {
		code = 1
		return
	}
	if len(tx.PublicKey) != ed25519.PublicKeySize*2 {
		code = 2
		return
	}
	if len(tx.Signature) != ed25519.SignatureSize*2 {
		code = 3
		return
	}
	if !tx.IsVerified() {
		code = 4
		return
	}
	switch tx.Command {
	case PublishMixDescriptor:
	case AddConsensusDocument:
	case AddNewAuthority:
		code = 0
	default:
		code = 5
	}

	return
}

func (app *KatzenmintApplication) updateMixDescriptor(desc *pki.MixDescriptor) (err error) {
	return
}

func (app *KatzenmintApplication) executeTx(tx *transaction) (err error) {
	switch tx.Command {
	case PublishMixDescriptor:
		var verifier cert.Verifier
		verifier, err = s11n.GetVerifierFromDescriptor([]byte(tx.Payload))
		if err != nil {
			return
		}
		// TODO: checkout epoch
		var desc *pki.MixDescriptor
		desc, err = s11n.VerifyAndParseDescriptor(verifier, []byte(tx.Payload), 0)
		if err != nil {
			return
		}
		// ensured the descriptor is signed by the user
		var pubKey *eddsa.PublicKey
		if !desc.IdentityKey.Equal(pubKey) {
			return
		}
		// make sure the descriptor is from authorized peerr
		if !app.state.isDescriptorAuthorized(desc) {
			return
		}
		fmt.Printf("got mix descriptor: %+v\n, should update the descriptor!!\n", desc)
		// TODO: update mixes descriptor in storage (database)
		err = app.updateMixDescriptor(desc)
		if err != nil {
			return
		}
	case AddConsensusDocument:
		err = fmt.Errorf("transaction type not support yet")
	case AddNewAuthority:
		err = fmt.Errorf("transaction type not support yet")
	default:
		err = fmt.Errorf("transaction type not support yet")
	}
	return
}

func (app *KatzenmintApplication) DeliverTx(req abcitypes.RequestDeliverTx) abcitypes.ResponseDeliverTx {
	code, tx := app.isTxValid(req.Tx)
	if code != 0 {
		return abcitypes.ResponseDeliverTx{Code: code}
	}
	err := app.executeTx(tx)
	if err != nil {
		code = 2
	}
	key := fmt.Sprintf("%s.%s", descriptorsBucket, tx.PublicKey)
	val := tx.Payload
	// TODO: use raw byte in struct
	err = app.currentBatch.Set([]byte(key), []byte(val))
	if err != nil {
		panic(err)
	}
	return abcitypes.ResponseDeliverTx{Code: code}
}

// TODO: gas formula
func (app *KatzenmintApplication) CheckTx(req abcitypes.RequestCheckTx) abcitypes.ResponseCheckTx {
	code, _ := app.isTxValid(req.Tx)
	return abcitypes.ResponseCheckTx{Code: code, GasWanted: 1}
}

func (app *KatzenmintApplication) Commit() abcitypes.ResponseCommit {
	_ = app.currentBatch.Commit()
	return abcitypes.ResponseCommit{Data: []byte{}}
}

// Note, no proof is included here
func (app *KatzenmintApplication) Query(query abcitypes.RequestQuery) (resQuery abcitypes.ResponseQuery) {

	resQuery.Key = query.Data

	item, err := app.currentBatch.Get(resQuery.Key)
	fmt.Printf("Item: %+v\n", item)
	if err != nil {
		if err == badger.ErrKeyNotFound {
			resQuery.Log = "does not exist"
		} else {
			panic(err)
		}
	} else {
		item.Value(func(val []byte) error {
			resQuery.Log = "exists"
			resQuery.Value = val
			return nil
		})
	}
	return
}

// TODO: state sync connection
func (app *KatzenmintApplication) ListSnapshots(req abcitypes.RequestListSnapshots) (res abcitypes.ResponseListSnapshots) {
	return
}

func (app *KatzenmintApplication) OfferSnapshot(req abcitypes.RequestOfferSnapshot) (res abcitypes.ResponseOfferSnapshot) {
	return
}

func (app *KatzenmintApplication) LoadSnapshotChunk(req abcitypes.RequestLoadSnapshotChunk) (res abcitypes.ResponseLoadSnapshotChunk) {
	return
}

func (app *KatzenmintApplication) ApplySnapshotChunk(req abcitypes.RequestApplySnapshotChunk) (res abcitypes.ResponseApplySnapshotChunk) {
	return
}

func (KatzenmintApplication) InitChain(req abcitypes.RequestInitChain) abcitypes.ResponseInitChain {
	return abcitypes.ResponseInitChain{}
}

func (app *KatzenmintApplication) BeginBlock(req abcitypes.RequestBeginBlock) abcitypes.ResponseBeginBlock {
	app.currentBatch = app.state.NewTransaction(true)
	return abcitypes.ResponseBeginBlock{}
}

func (KatzenmintApplication) EndBlock(req abcitypes.RequestEndBlock) abcitypes.ResponseEndBlock {
	return abcitypes.ResponseEndBlock{}
}
