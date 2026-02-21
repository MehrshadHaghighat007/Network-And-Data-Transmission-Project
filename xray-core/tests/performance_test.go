package tests // تغییر نام پکیج به tests

import (
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
	// ایمپورت کردن پکیج اصلی
)

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func BenchmarkEncryption(b *testing.B) {
	key := make([]byte, 32)
	// استفاده از پیشوند reflex برای دسترسی به توابع پکیج اصلی
	session, _ := reflex.NewSession(key)
	data := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// اضxافه کردن پیشوند reflex.
		_, _ = session.CreateFrame(reflex.FrameTypeData, data)
	}
}

func BenchmarkMemoryAllocation(b *testing.B) {
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key)
	data := make([]byte, 1024)
	writer := discardWriter{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// اضافه کردن پیشوند reflex.
		_ = session.WriteFrame(writer, reflex.FrameTypeData, data)
	}
}
