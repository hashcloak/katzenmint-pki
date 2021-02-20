package main

import (
	"encoding/json"
	"fmt"

	// "github.com/ugorji/go/codec"
	"github.com/dgraph-io/badger"
	// "github.com/hashcloak/pki/internal/s11n"
	"github.com/katzenpost/core/pki"
	abcitypes "github.com/tendermint/tendermint/abci/types"
)

type KatzenmintApplication struct {
	db           *badger.DB
	currentBatch *badger.Txn
}

// TODO: find a better way to represent the transaction
type transaction struct {
	Version string
	Command Command
	Payload string
}

var (
	_ abcitypes.Application = (*KatzenmintApplication)(nil)
	// jsonHandle *codec.JsonHandle
)

// TODO: check codec json handle
// dec := codec.NewDecoderBytes(rawTx, jsonHandle)
// func init() {
// 	jsonHandle = new(codec.JsonHandle)
// 	jsonHandle.Canonical = true
// 	jsonHandle.IntegerAsString = 'A'
// 	jsonHandle.MapKeyAsString = true
// }

func NewKatzenmintApplication(db *badger.DB) *KatzenmintApplication {
	return &KatzenmintApplication{
		db: db,
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
	switch tx.Command {
	case PublishMixDescriptor:
		code = 0
	case AddConsensusDocument:
		code = 2
	case AddNewAuthority:
		code = 2
	default:
		code = 2
	}

	return
}

func (app *KatzenmintApplication) executeTx(tx *transaction) (err error) {
	switch tx.Command {
	case PublishMixDescriptor:
		mixDescriptor := new(pki.MixDescriptor)
		if err = json.Unmarshal([]byte(tx.Payload), mixDescriptor); err != nil {
			return
		} else {
			// TODO: verify descriptor by epoch
			fmt.Println("")
			fmt.Printf("%+v\n", mixDescriptor)
			fmt.Println("")
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
	// parts := bytes.Split(req.Tx, []byte("="))
	// key, value := parts[0], parts[1]
	// err := app.currentBatch.Set(key, value)
	// if err != nil {
	// 	panic(err)
	// }
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

	if err := app.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(resQuery.Key)
		fmt.Printf("Item: %+v\n", item)
		if err != nil && err != badger.ErrKeyNotFound {
			return nil
		}
		if err == badger.ErrKeyNotFound {
			resQuery.Log = "does not exist"
		} else {
			return item.Value(func(val []byte) error {
				resQuery.Log = "exists"
				resQuery.Value = val
				return nil
			})
		}
		return nil
	}); err != nil {
		panic(err)
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
	app.currentBatch = app.db.NewTransaction(true)
	return abcitypes.ResponseBeginBlock{}
}

func (KatzenmintApplication) EndBlock(req abcitypes.RequestEndBlock) abcitypes.ResponseEndBlock {
	return abcitypes.ResponseEndBlock{}
}
