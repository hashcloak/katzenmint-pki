package tendermint

import (
	abcitypes "github.com/tendermint/tendermint/abci/types"
)

type KatzenmintApplication struct {
}

func NewKatzenmintApplication() *KatzenmintApplication {
	return &KatzenmintApplication{}
}

// Info connection

func (app *KatzenmintApplication) Info(req abcitypes.RequestInfo) *abcitypes.ResponseInfo {
	return &abcitypes.ResponseInfo{}
}

func (app *KatzenmintApplication) SetOption(req abcitypes.RequestSetOption) *abcitypes.ResponseSetOption {
	return &abcitypes.ResponseSetOption{}
}

func (app *KatzenmintApplication) Query(req abcitypes.RequestQuery) *abcitypes.ResponseQuery {
	return &abcitypes.ResponseQuery{}
}

// Mempool connection

func (app *KatzenmintApplication) CheckTx(req abcitypes.RequestCheckTx) *abcitypes.ResponseCheckTx {
	return &abcitypes.ResponseCheckTx{}
}

// Consensus connection

func (app *KatzenmintApplication) InitChain(req abcitypes.RequestInitChain) *abcitypes.ResponseInitChain {
	return &abcitypes.ResponseInitChain{}
}

func (app *KatzenmintApplication) BeginBlock(req abcitypes.RequestBeginBlock) *abcitypes.ResponseBeginBlock {
	return &abcitypes.ResponseBeginBlock{}
}

func (app *KatzenmintApplication) DeliverTx(req abcitypes.RequestDeliverTx) *abcitypes.ResponseDeliverTx {
	return &abcitypes.ResponseDeliverTx{}
}

func (app *KatzenmintApplication) EndBlock(req abcitypes.RequestEndBlock) *abcitypes.ResponseEndBlock {
	return &abcitypes.ResponseEndBlock{}
}

func (app *KatzenmintApplication) Commit(req abcitypes.RequestCommit) *abcitypes.ResponseCommit {
	return &abcitypes.ResponseCommit{}
}

// Snapshot connection

func (app *KatzenmintApplication) ListSnapshots(req abcitypes.RequestListSnapshots) *abcitypes.ResponseListSnapshots {
	return &abcitypes.ResponseListSnapshots{}
}

func (app *KatzenmintApplication) LoadSnapshotChunk(req abcitypes.RequestLoadSnapshotChunk) *abcitypes.ResponseLoadSnapshotChunk {
	return &abcitypes.ResponseLoadSnapshotChunk{}
}

func (app *KatzenmintApplication) OfferSnapshot(req abcitypes.RequestOfferSnapshot) *abcitypes.ResponseOfferSnapshot {
	return &abcitypes.ResponseOfferSnapshot{}
}

func (app *KatzenmintApplication) ApplySnapshotChunk(req abcitypes.RequestApplySnapshotChunk) *abcitypes.ResponseApplySnapshotChunk {
	return &abcitypes.ResponseApplySnapshotChunk{}
}
