package reflex

import (
	"testing"
)

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func BenchmarkEncryption(b *testing.B) {
	key := make([]byte, 32)
	session, _ := NewSession(key)
	data := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = session.CreateFrame(FrameTypeData, data)
	}
}

func BenchmarkMemoryAllocation(b *testing.B) {
	key := make([]byte, 32)
	session, _ := NewSession(key)
	data := make([]byte, 1024)
	writer := discardWriter{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = session.WriteFrame(writer, FrameTypeData, data)
	}
}
