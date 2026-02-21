package reflex

import (
	"crypto/ed25519"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

func GenerateKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	return priv, pub, err
}

func DeriveSharedKey(priv []byte, pub []byte) []byte {
	sum := sha256.Sum256(append(priv, pub...))
	return sum[:]
}

func DeriveSessionKey(sharedKey []byte, salt []byte) []byte {
	k := make([]byte, 32)
	h := hkdf.New(sha256.New, sharedKey, salt, nil)
	_, _ = io.ReadFull(h, k) // ارور توسط لینتر با _, _ نادیده گرفته شد
	return k
}
