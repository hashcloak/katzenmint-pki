package katzenmint

import (
	"encoding/hex"
	"fmt"
)

// DecodeHex return byte of the given hex string
// return nil if the src is not valid hex string
func DecodeHex(src string) (out []byte) {
	slen := len(src)
	if slen <= 0 {
		return
	}
	if (slen % 2) > 0 {
		src = fmt.Sprintf("0%s", src)
	}
	out, _ = hex.DecodeString(src)
	return
}

// EncodeHex return encoded hex string of the given
// bytes
func EncodeHex(src []byte) (out string) {
	out = hex.EncodeToString(src)
	return
}
