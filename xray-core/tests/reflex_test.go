package tests

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestEncryption(t *testing.T) {
	testKey := make([]byte, 32)
	session, _ := reflex.NewSession(testKey)

	original := []byte("Reflex Secure Protocol Test Data")
	nonce := make([]byte, 12)

	// استفاده از AEAD بزرگ
	encrypted := session.AEAD.Seal(nil, nonce, original, nil)
	decrypted, err := session.AEAD.Open(nil, nonce, encrypted, nil)

	if err != nil || !bytes.Equal(original, decrypted) {
		t.Fatal("Encryption check failed!")
	}
}
