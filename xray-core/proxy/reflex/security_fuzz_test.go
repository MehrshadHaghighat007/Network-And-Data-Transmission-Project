package reflex

import (
	"bytes"
	"testing"
)

// FuzzReadFrame بررسی می‌کند که دیتای مخرب باعث Panic نشود.
func FuzzReadFrame(f *testing.F) {
	key := make([]byte, 32) // کلید تست
	session, _ := NewSession(key)

	// چند دیتای اولیه برای راهنمایی فازر
	f.Add([]byte{0, 5, 1, 0, 0, 0}) // فریم خیلی کوتاه
	f.Add(make([]byte, 100))        // دیتای خالی

	f.Fuzz(func(t *testing.T, data []byte) {
		reader := bytes.NewReader(data)
		// نباید در هیچ حالتی Panic رخ دهد
		_, _ = session.ReadFrame(reader)
	})
}
