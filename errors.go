package katzenmint

import (
	"fmt"
)

type KatzenmintError struct {
	error

	Msg  string
	Code uint32
}

func (err KatzenmintError) Error() string {
	return fmt.Sprintf("error (%d): %s", err.Code, err.Msg)
}

var (
	ErrTxIsNotValidJSON     = KatzenmintError{Msg: "transaction is not valid json string", Code: 1}
	ErrTxWrongPublicKeySize = KatzenmintError{Msg: "wrong public key size in transaction", Code: 2}
	ErrTxWrongSignatureSize = KatzenmintError{Msg: "wrong public key size in transaction", Code: 3}
	ErrTxWrongSignature     = KatzenmintError{Msg: "wrong signature in transaction", Code: 4}
	ErrTxNonAuthorized      = KatzenmintError{Msg: "non authorized authority", Code: 5}
	ErrTxCommandNotFound    = KatzenmintError{Msg: "transaction command not found", Code: 6}
)
