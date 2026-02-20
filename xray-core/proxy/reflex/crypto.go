package reflex

import (
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func GenerateKeyPair() ([32]byte, [32]byte, error) {
	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return priv, pub, err
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv, pub, nil
}

func DeriveSharedKey(priv, peerPub [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &priv, &peerPub)
	return shared
}

func DeriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	kdf := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	kdf.Read(sessionKey)
	return sessionKey
}
