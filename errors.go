package katzenmint

import (
	"fmt"

	abcitypes "github.com/tendermint/tendermint/abci/types"
)

type KatzenmintError struct {
	error

	Code uint32
	Msg  string
}

func (err KatzenmintError) Error() string {
	return fmt.Sprintf("error (%d): %s", err.Code, err.Msg)
}

var (
	// Transaction Common Errors
	ErrTxIsNotValidJSON     = KatzenmintError{Code: 0x01, Msg: "transaction is not valid json string"}
	ErrTxWrongPublicKeySize = KatzenmintError{Code: 0x02, Msg: "wrong public key size in transaction"}
	ErrTxWrongSignatureSize = KatzenmintError{Code: 0x03, Msg: "wrong public key size in transaction"}
	ErrTxWrongSignature     = KatzenmintError{Code: 0x04, Msg: "wrong signature in transaction"}

	// Transaction Specific Errors
	ErrTxDescInvalidVerifier   = KatzenmintError{Code: 0x11, Msg: "cannot get descriptor verifier"}
	ErrTxDescFalseVerification = KatzenmintError{Code: 0x12, Msg: "cannot verify and parse descriptor"}
	ErrTxNonAuthorized         = KatzenmintError{Code: 0x13, Msg: "non authorized authority"}
	ErrTxCommandNotFound       = KatzenmintError{Code: 0x14, Msg: "transaction command not found"}

	// Query Errors
	ErrQueryInvalidFormat    = KatzenmintError{Code: 0x21, Msg: "error query format"}
	ErrQueryUnsupported      = KatzenmintError{Code: 0x22, Msg: "unsupported query"}
	ErrQueryEpochFailed      = KatzenmintError{Code: 0x23, Msg: "cannot obtain epoch for the current height"}
	ErrQueryNoDocument       = KatzenmintError{Code: 0x24, Msg: "requested epoch has passed and will never get a document"}
	ErrQueryDocumentNotReady = KatzenmintError{Code: 0x25, Msg: "document for requested epoch is not ready yet"}
	ErrQueryDocumentUnknown  = KatzenmintError{Code: 0x26, Msg: "unknown failure for document query"}
)

func parseErrorResponse(err KatzenmintError, resp *abcitypes.ResponseQuery) {
	resp.Code = err.Code
	resp.Log = err.Msg
}
