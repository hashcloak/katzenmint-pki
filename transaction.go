package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"

	"github.com/katzenpost/core/crypto/eddsa"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
)

// TODO: cache the hex decode result?
// signTransaction represents the transaction used to make transaction hash
type signTransaction struct {
	// version
	Version string

	// Epoch
	Epoch uint64

	// command
	Command Command

	// hex encoded ed25519 public key (should not be 0x prefxied)
	// TODO: is there better way to take PublicKey?
	PublicKey string

	// payload (mix descriptor/pki document/authority)
	Payload string
}

// TODO: find a better way to represent the transaction
// maybe add nonce? switch to rlp encoding?
type transaction struct {
	// version
	Version string

	// Epoch
	Epoch uint64

	// command
	Command Command

	// hex encoded ed25519 public key (should not be 0x prefxied)
	PublicKey string

	// hex encoded ed25519 signature (should not be 0x prefixed)
	Signature string

	// json encoded payload (mix descriptor/pki document/authority)
	Payload string
}

// SerializeHash return the serialize hash that user signed of the given transaction
func (tx *transaction) SerializeHash() (hash [32]byte) {
	signTx := new(signTransaction)
	signTx.Version = tx.Version
	signTx.Epoch = tx.Epoch
	signTx.Command = tx.Command
	signTx.PublicKey = tx.PublicKey
	signTx.Payload = tx.Payload
	src, err := json.Marshal(signTx)
	if err != nil {
		return
	}
	hash = sha256.Sum256(src)
	return
}

func (tx *transaction) IsVerified() (isVerified bool) {
	msgHash := tx.SerializeHash()
	if len(msgHash) <= 0 {
		return
	}
	pub := DecodeHex(tx.PublicKey)
	sig := DecodeHex(tx.Signature)
	pubKey := ed25519.PublicKey(pub)
	isVerified = ed25519.Verify(pubKey, msgHash[:], sig)
	return
}

// PublicKeyBytes returns public key bytes of the given transaction
func (tx *transaction) PublicKeyBytes() (pk []byte) {
	pk = DecodeHex(tx.PublicKey)
	return
}

// PublicKeyByteArray returns public key bytes of the given transaction
func (tx *transaction) PublicKeyByteArray() (pk [eddsa.PublicKeySize]byte) {
	pubkey := DecodeHex(tx.PublicKey)
	copy(pk[:], pubkey)
	return
}

// Address returns public address of the given transaction
func (tx *transaction) Address() string {
	v := abcitypes.UpdateValidator(tx.PublicKeyBytes(), 0, "")
	pubkey, err := cryptoenc.PubKeyFromProto(v.PubKey)
	if err != nil {
		return ""
	}
	return string(pubkey.Address())
}
