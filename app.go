package main

import (
	"crypto/ed25519"
	// "crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/dgraph-io/badger"
	"github.com/hashcloak/katzenmint-pki/internal/s11n"
	"github.com/katzenpost/core/crypto/cert"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/pki"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	// "github.com/tendermint/tendermint/version"
	// cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
)

const (
	ProtocolVersion uint64 = 0x0
)

var (
	_ abcitypes.Application = (*KatzenmintApplication)(nil)
)

type KatzenmintApplication struct {
	state *KatzenmintState

	// TODO: use tendermint logger?
	// logger log.Logger
}

func NewKatzenmintApplication(db *badger.DB) *KatzenmintApplication {
	state := NewKatzenmintState(db)
	return &KatzenmintApplication{
		state: state,
	}
}

func (app *KatzenmintApplication) Info(req abcitypes.RequestInfo) abcitypes.ResponseInfo {
	return abcitypes.ResponseInfo{
		// Data:             fmt.Sprintf("{\"blockHeight\":%v}", app.state.blockHeight),
		// Version:          version.ABCIVersion,
		// AppVersion:       ProtocolVersion,
		// LastBlockHeight:  int64(app.state.blockHeight),
		// LastBlockAppHash: make([]byte, 8),
	}
}

func (app *KatzenmintApplication) SetOption(req abcitypes.RequestSetOption) abcitypes.ResponseSetOption {
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
		addr := tx.Address()
		if !app.state.isAuthorized(addr) {
			fmt.Println("Non authorized authority")
			code = 5
			return
		}
		code = 0
	default:
		code = 6
	}

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
		payload := []byte(tx.Payload)
		desc, err = s11n.VerifyAndParseDescriptor(verifier, payload, tx.Epoch)
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
		if err = s11n.IsDescriptorWellFormed(desc, tx.Epoch); err != nil {
			return
		}
		err = app.state.updateMixDescriptor(payload, desc, tx.Epoch)
		if err != nil {
			return
		}
	case AddConsensusDocument:
		var verifier cert.Verifier
		payload := []byte(tx.Payload)
		var doc *pki.Document
		doc, err = s11n.VerifyAndParseDocument(payload, verifier)
		if err != nil {
			return
		} else if doc.Epoch != tx.Epoch {
			err = s11n.ErrInvalidEpoch
			return
		}
		if err = s11n.IsDocumentWellFormed(doc); err != nil {
			return
		}
		if !app.state.isDocumentAuthorized(doc) {
			return
		}
		err = app.state.updateDocument(payload, doc, tx.Epoch)
		if err != nil {
			return
		}
	case AddNewAuthority:
		// TODO: update validators
		var authority *Authority
		// pk := tx.PublicKeyBytesArray()
		payload := []byte(tx.Payload)
		authority, err = app.state.VerifyAndParseAuthority(payload)
		if err != nil {
			fmt.Printf("failed to parse authority: %+v\n", err)
			return
		}
		err = app.state.updateAuthority(payload, abcitypes.UpdateValidator(authority.IdentityKey.Bytes(), authority.Power, ""))
		if err != nil {
			fmt.Printf("failed to update authority: %+v\n", err)
			return
		}
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
	return abcitypes.ResponseDeliverTx{Code: code}
}

// TODO: gas formula
func (app *KatzenmintApplication) CheckTx(req abcitypes.RequestCheckTx) abcitypes.ResponseCheckTx {
	code, _ := app.isTxValid(req.Tx)
	return abcitypes.ResponseCheckTx{Code: code, GasWanted: 1}
}

// TODO: should update the validators map after commit
func (app *KatzenmintApplication) Commit() abcitypes.ResponseCommit {
	app.state.Commit()
	return abcitypes.ResponseCommit{Data: []byte{}}
}

// Note, no proof is included here
// TODO: include merkle proof?
func (app *KatzenmintApplication) Query(rquery abcitypes.RequestQuery) (resQuery abcitypes.ResponseQuery) {

	kquery := new(query)
	if err := json.Unmarshal(rquery.Data, kquery); err != nil {
		resQuery.Log = "unsupported query"
		// resQuery.value = "unsupported query"
		return
	}
	switch kquery.Command {
	case GetConsensus:
		doc, err := app.state.documentForEpoch(kquery.Epoch)
		if err != nil {
			fmt.Printf("Peer: Failed to retrieve document for epoch '%v': %v", kquery.Epoch, err)
			resQuery.Log = "does not exist"
		} else {
			resQuery.Value = doc
		}
	default:
		resQuery.Log = "unsupported query"
		// resQuery.value = "unsupported query"
		return
	}
	return
}

func (app *KatzenmintApplication) InitChain(req abcitypes.RequestInitChain) abcitypes.ResponseInitChain {
	app.state.transactionBatch = app.state.NewTransaction(true)
	for _, v := range req.Validators {
		err := app.state.updateAuthority(nil, v)
		if err != nil {
			fmt.Printf("Error updating validators: %+v\n", err)
		}
	}
	_ = app.state.transactionBatch.Commit()
	app.state.transactionBatch = nil
	return abcitypes.ResponseInitChain{}
}

// Track the block hash and header information
func (app *KatzenmintApplication) BeginBlock(req abcitypes.RequestBeginBlock) abcitypes.ResponseBeginBlock {
	app.state.BeginBlock()

	// Punish validators who committed equivocation.
	for _, ev := range req.ByzantineValidators {
		if ev.Type == abcitypes.EvidenceType_DUPLICATE_VOTE {
			addr := string(ev.Validator.Address)
			if pubKey, ok := app.state.GetAuthorized(addr); ok {
				_ = app.state.updateAuthority(nil, abcitypes.ValidatorUpdate{
					PubKey: pubKey,
					Power:  ev.Validator.Power - 1,
				})
				fmt.Println("Decreased val power by 1 because of the equivocation", addr)
			} else {
				fmt.Println("Wanted to punish val, but can't find it", addr)
			}
		}
	}
	return abcitypes.ResponseBeginBlock{}
}

// Update validators
func (app *KatzenmintApplication) EndBlock(req abcitypes.RequestEndBlock) abcitypes.ResponseEndBlock {
	// will there be race condition?
	return abcitypes.ResponseEndBlock{ValidatorUpdates: app.state.validatorUpdates}
}

// TODO: state sync connection
func (app *KatzenmintApplication) ListSnapshots(req abcitypes.RequestListSnapshots) (res abcitypes.ResponseListSnapshots) {
	return
}

func (app *KatzenmintApplication) OfferSnapshot(req abcitypes.RequestOfferSnapshot) (res abcitypes.ResponseOfferSnapshot) {
	res.Result = abcitypes.ResponseOfferSnapshot_ABORT
	return
}

func (app *KatzenmintApplication) LoadSnapshotChunk(req abcitypes.RequestLoadSnapshotChunk) (res abcitypes.ResponseLoadSnapshotChunk) {
	return
}

func (app *KatzenmintApplication) ApplySnapshotChunk(req abcitypes.RequestApplySnapshotChunk) (res abcitypes.ResponseApplySnapshotChunk) {
	res.Result = abcitypes.ResponseApplySnapshotChunk_ABORT
	return
}
