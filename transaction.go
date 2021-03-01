package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
)

// signTransaction represents the transaction used to make transaction hash
type signTransaction struct {
	// version
	Version string

	// command
	Command Command

	// hex encoded ed25519 public key (should not be 0x prefxied)
	PublicKey string

	// payload (mix descriptor/pki document/authority)
	Payload string
}

// TODO: find a better way to represent the transaction
// maybe add nonce? switch to rlp encoding?
type transaction struct {
	// version
	Version string

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
