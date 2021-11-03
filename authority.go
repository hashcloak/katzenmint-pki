package katzenmint

import (
	"github.com/ugorji/go/codec"
)

// Authority represents authority in katzenmint.
type Authority struct {
	// Auth is the prefix of the authority.
	Auth string

	// PubKey is the validator's public key.
	PubKey []byte

	// KeyType is the validator's key type.
	KeyType string

	// Power is the voting power of the authority.
	Power int64
}

/*
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
*/

func VerifyAndParseAuthority(payload []byte) (*Authority, error) {
	authority := new(Authority)
	dec := codec.NewDecoderBytes(payload, jsonHandle)
	if err := dec.Decode(authority); err != nil {
		return nil, err
	}
	// TODO: check authority
	return authority, nil
}
