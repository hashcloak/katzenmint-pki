package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/katzenpost/core/crypto/rand"
)

type Payload struct {
	Text   string
	Number int
}

func TestTransaction(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate key pair: %+v\n", err)
	}
	payload, err := json.Marshal(Payload{
		Text:   "test",
		Number: 1,
	})
	if err != nil {
		t.Fatalf("cannot json marshal payload: %+v\n", err)
	}
	tx := new(transaction)
	tx.Version = "1.0"
	tx.Epoch = 10
	tx.Command = 1
	tx.Payload = string(payload)
	tx.PublicKey = EncodeHex(pubKey[:])
	msgHash := tx.SerializeHash()
	sig := ed25519.Sign(privKey, msgHash[:])
	tx.Signature = EncodeHex(sig[:])
	if !tx.IsVerified() {
		t.Fatalf("transaction is not verified: %+v\n", tx)
	}
	z, _ := json.Marshal(tx)
	fmt.Println(string(z))
}
