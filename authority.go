package katzenmint

import (
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
	"github.com/ugorji/go/codec"
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

func bytesToAddress(pk [eddsa.PublicKeySize]byte) string {
	p := make([]byte, eddsa.PublicKeySize)
	copy(p, pk[:])
	v := abcitypes.UpdateValidator(p, 0, "")
	pubkey, err := cryptoenc.PubKeyFromProto(v.PubKey)
	if err != nil {
		return ""
	}
	return string(pubkey.Address())
}

func VerifyAndParseAuthority(payload []byte) (*Authority, error) {
	authority := new(Authority)
	dec := codec.NewDecoderBytes(payload, jsonHandle)
	if err := dec.Decode(authority); err != nil {
		return nil, err
	}
	// TODO: check authority
	return authority, nil
}
