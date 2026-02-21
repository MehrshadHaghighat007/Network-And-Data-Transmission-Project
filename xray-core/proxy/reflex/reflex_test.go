package reflex

import (
	"bytes"
	"testing"
)

func TestEncryption(t *testing.T) {
	// ۱. ایجاد کلید تستی
	testKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		testKey[i] = byte(i)
	}

	// ۲. ایجاد سشن
	session, err := NewSession(testKey)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// ۳. دیتای تستی
	original := []byte("Reflex Secure Protocol Test Data")
	nonce := make([]byte, 12)

	// ۴. تست رمزنگاری
	encrypted := session.aead.Seal(nil, nonce, original, nil)

	// ۵. تست رمزگشایی
	decrypted, err := session.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(original, decrypted) {
		t.Fatal("Data integrity check failed!")
	}

	t.Log("SUCCESS: AEAD Encryption/Decryption verified.")
}
