package main

import (
	"bytes"
	"testing"
)

type decodeTest struct {
	Src string
	Out []byte
}

var (
	decodeHexTests = []decodeTest{
		{
			Src: "6b61747a656e6d696e74",
			Out: []byte{
				107, 97, 116, 122, 101, 110, 109, 105, 110, 116,
			},
		},
	}
)

func TestDecodeHex(t *testing.T) {
	for _, test := range decodeHexTests {
		b := DecodeHex(test.Src)
		if !bytes.Equal(test.Out, b) {
			t.Fatalf("decode hex results should be equal")
		}
	}
}
