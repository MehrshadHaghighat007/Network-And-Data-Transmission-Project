package tests

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

// تابع TestWeakKeys از اینجا حذف شد تا تداخل ایجاد نشود

func FuzzReadFrame(f *testing.F) {
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key)
	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		reader := bytes.NewReader(data)
		// هدف فازینگ این است که برنامه با ورودی تصادفی کرش نکند
		_, _ = session.ReadFrame(reader)
	})
}
