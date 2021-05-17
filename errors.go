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
	ErrTxIsNotValidJSON     = KatzenmintError{Msg: "transaction is not valid json string", Code: 0x01}
	ErrTxWrongPublicKeySize = KatzenmintError{Msg: "wrong public key size in transaction", Code: 0x02}
	ErrTxWrongSignatureSize = KatzenmintError{Msg: "wrong public key size in transaction", Code: 0x03}
	ErrTxWrongSignature     = KatzenmintError{Msg: "wrong signature in transaction", Code: 0x04}

	ErrTxDescInvalidVerifier   = KatzenmintError{Msg: "cannot get descriptor verifier", Code: 0x11}
	ErrTxDescFalseVerification = KatzenmintError{Msg: "cannot verify and parse descriptor", Code: 0x12}
	ErrTxDescNotSelfSigned     = KatzenmintError{Msg: "descriptor is not self-signed", Code: 0x13}

	ErrTxNonAuthorized   = KatzenmintError{Msg: "non authorized authority", Code: 0x31}
	ErrTxCommandNotFound = KatzenmintError{Msg: "transaction command not found", Code: 0x32}
)
