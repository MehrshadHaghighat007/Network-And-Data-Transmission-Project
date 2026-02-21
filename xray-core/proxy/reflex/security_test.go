package reflex

import (
	"crypto/subtle"
	"testing"
)

func TestWeakKeys(t *testing.T) {
	// تست کلید با طول نامعتبر (باید ۳۲ بایت باشد)
	shortKey := make([]byte, 16)
	_, err := NewSession(shortKey)
	if err == nil {
		t.Error("Security Risk: Session accepted a weak/short key!")
	} else {
		t.Log("Success: Weak key rejected.")
	}
}

func TestConstantTimeUUID(t *testing.T) {
	// تست مقایسه امن UUID
	uuid1 := []byte("12345678-1234-1234-1234-123456789012")
	uuid2 := []byte("12345678-1234-1234-1234-123456789013")

	if subtle.ConstantTimeCompare(uuid1, uuid2) == 1 {
		t.Error("UUIDs should not match")
	}
}
