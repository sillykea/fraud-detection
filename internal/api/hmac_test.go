package api_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func hmacHex(key, msg []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil))
}
