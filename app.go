package katzenmint

import (
	"crypto/ed25519"
	"encoding/binary"

	// "crypto/sha256"
	"fmt"

	"github.com/hashcloak/katzenmint-pki/s11n"
	"github.com/katzenpost/core/crypto/eddsa"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	tmcrypto "github.com/tendermint/tendermint/proto/tendermint/crypto"
	dbm "github.com/tendermint/tm-db"
	"github.com/ugorji/go/codec"
	// "github.com/tendermint/tendermint/version"
	// cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
)

const (
	ProtocolVersion string = "v0.0.1"
)

var (
	_ abcitypes.Application = (*KatzenmintApplication)(nil)
)

type KatzenmintApplication struct {
	state *KatzenmintState

	// TODO: use tendermint logger?
	// logger log.Logger
}

func NewKatzenmintApplication(db dbm.DB) *KatzenmintApplication {
	state := NewKatzenmintState(db)
	return &KatzenmintApplication{
		state: state,
	}
}

func (app *KatzenmintApplication) Info(req abcitypes.RequestInfo) abcitypes.ResponseInfo {
	epoch := make([]byte, 8)
	binary.PutUvarint(epoch, app.state.currentEpoch)
	return abcitypes.ResponseInfo{
		Data: EncodeHex(epoch),
		// Version:          version.ABCIVersion,
		// AppVersion:       ProtocolVersion,
		LastBlockHeight:  app.state.blockHeight,
		LastBlockAppHash: app.state.appHash,
	}
}

func (app *KatzenmintApplication) SetOption(req abcitypes.RequestSetOption) abcitypes.ResponseSetOption {
	return abcitypes.ResponseSetOption{}
}

func (app *KatzenmintApplication) isTxValid(rawTx []byte) (code uint32, tx *Transaction) {
	tx = new(Transaction)
	dec := codec.NewDecoderBytes(rawTx, jsonHandle)
	if err := dec.Decode(tx); err != nil {
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

func (app *KatzenmintApplication) executeTx(tx *Transaction) error {
	// check for the epoch relative to the current epoch
	if tx.Epoch < app.state.currentEpoch-1 || tx.Epoch > app.state.currentEpoch+1 {
		return fmt.Errorf("expect transaction for epoch within +-1 to %d, but got epoch %d", app.state.currentEpoch, tx.Epoch)
	}
	switch tx.Command {
	case PublishMixDescriptor:
		verifier, err := s11n.GetVerifierFromDescriptor([]byte(tx.Payload))
		if err != nil {
			return err
		}
		payload := []byte(tx.Payload)
		desc, err := s11n.VerifyAndParseDescriptor(verifier, payload, tx.Epoch)
		if err != nil {
			return err
		}
		// ensure the descriptor is signed by the user
		var pubKey *eddsa.PublicKey
		if !desc.IdentityKey.Equal(pubKey) {
			return fmt.Errorf("descriptor is not self-signed")
		}
		// make sure the descriptor is from authorized peerr
		if !app.state.isDescriptorAuthorized(desc) {
			return fmt.Errorf("descriptor is not authorized")
		}
		err = app.state.updateMixDescriptor(payload, desc, tx.Epoch)
		if err != nil {
			return fmt.Errorf("error updating descriptor: %v", err)
		}
	case AddConsensusDocument:
		payload := []byte(tx.Payload)
		doc, err := s11n.VerifyAndParseDocument(payload)
		if err != nil {
			return err
		} else if doc.Epoch != tx.Epoch {
			return s11n.ErrInvalidEpoch
		}
		if !app.state.isDocumentAuthorized(doc) {
			return fmt.Errorf("document is not authorized")
		}
		err = app.state.updateDocument(payload, doc, tx.Epoch)
		if err != nil {
			return fmt.Errorf("error updating document: %v", err)
		}
	case AddNewAuthority:
		// TODO: update validators
		payload := []byte(tx.Payload)
		authority, err := VerifyAndParseAuthority(payload)
		if err != nil {
			return fmt.Errorf("failed to parse authority: %v", err)
		}
		err = app.state.updateAuthority(payload, abcitypes.UpdateValidator(authority.IdentityKey.Bytes(), authority.Power, ""))
		if err != nil {
			return fmt.Errorf("error updating authority: %v", err)
		}
	default:
		return fmt.Errorf("transaction type not supported")
	}
	// Unreached
	return nil
}

func (app *KatzenmintApplication) DeliverTx(req abcitypes.RequestDeliverTx) abcitypes.ResponseDeliverTx {
	code, tx := app.isTxValid(req.Tx)
	if code != abcitypes.CodeTypeOK {
		return abcitypes.ResponseDeliverTx{Code: code}
	}
	err := app.executeTx(tx)
	if err != nil {
		return abcitypes.ResponseDeliverTx{Code: 0xFF, Log: err.Error()}
	}
	return abcitypes.ResponseDeliverTx{Code: abcitypes.CodeTypeOK}
}

// TODO: gas formula
func (app *KatzenmintApplication) CheckTx(req abcitypes.RequestCheckTx) abcitypes.ResponseCheckTx {
	code, _ := app.isTxValid(req.Tx)
	return abcitypes.ResponseCheckTx{Code: code, GasWanted: 1}
}

// TODO: should update the validators map after commit
func (app *KatzenmintApplication) Commit() abcitypes.ResponseCommit {
	appHash := app.state.Commit()
	return abcitypes.ResponseCommit{Data: appHash}
}

// Note, no proof is included here
// TODO: include merkle proof?
func (app *KatzenmintApplication) Query(rquery abcitypes.RequestQuery) (resQuery abcitypes.ResponseQuery) {

	kquery := new(Query)
	dec := codec.NewDecoderBytes(rquery.Data, jsonHandle)
	if err := dec.Decode(kquery); err != nil {
		resQuery.Log = "error query format"
		resQuery.Code = 0x1
		return
	}

	switch kquery.Command {
	default:
		resQuery.Log = "unsupported query"
		resQuery.Code = 0x2
	case GetConsensus:
		doc, proof, err := app.state.documentForEpoch(kquery.Epoch)
		if err != nil {
			fmt.Printf("Peer: Failed to retrieve document for epoch '%v': %v", kquery.Epoch, err)
			resQuery.Log = "document does not exist"
			resQuery.Code = 0x3
			return
		}
		resQuery.Key = proof.GetKey()
		resQuery.Value = doc
		resQuery.Height = int64(app.state.blockHeight)
		resQuery.ProofOps = &tmcrypto.ProofOps{
			Ops: []tmcrypto.ProofOp{proof.ProofOp()},
		}
	}
	return
}

func (app *KatzenmintApplication) InitChain(req abcitypes.RequestInitChain) abcitypes.ResponseInitChain {
	for _, v := range req.Validators {
		err := app.state.updateAuthority(nil, v)
		if err != nil {
			fmt.Printf("Error updating validators: %+v\n", err)
		}
	}
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
