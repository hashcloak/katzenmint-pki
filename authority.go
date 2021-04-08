package katzenmint

import (
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
)

// Authority represents authority in katzenmint.
type Authority struct {
	// Auth is the prefix of the authority.
	Auth string

	// IdentityKey is the node's identity (signing) key.
	IdentityKey *eddsa.PublicKey

	// LinkKey is the node's wire protocol public key.
	LinkKey *ecdh.PublicKey

	// Power is the voting power of the authority.
	Power int64
}
