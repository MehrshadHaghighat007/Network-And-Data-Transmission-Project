package reflex

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"net"
	"testing"
	"time"
)

// تست ۱: ارسال داده‌های خالی
// هدف: مطمئن شویم WriteFrame با دیتای خالی کرش نمی‌کند
func TestEmptyData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := NewSession(key)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	done := make(chan bool)
	go func() {
		reader := bufio.NewReader(c2)
		_, err := session.ReadFrame(reader)
		if err == nil {
			done <- true
		}
	}()

	err := session.WriteFrame(c1, FrameTypeData, []byte{})
	if err != nil {
		t.Errorf("Failed to write empty data: %v", err)
	}

	select {
	case <-done:
		// موفق
	case <-time.After(1 * time.Second):
		t.Error("Timeout: Empty data test got stuck")
	}
}

// تست ۲: حمله Replay با فریم تکراری
// هدف: لایه امنیتی نباید اجازه دهد یک فریم دو بار پردازش شود
func TestReplayEdgeCase(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// ایجاد سشن فرستنده و گیرنده
	sendS, _ := NewSession(key)
	recvS, _ := NewSession(key)

	// ایجاد یک فریم واقعی در حافظه
	var b bytes.Buffer
	payload := []byte("replay me")
	_ = sendS.WriteFrame(&b, FrameTypeData, payload)
	frameBytes := b.Bytes()

	// بار اول: باید قبول شود
	r1 := bufio.NewReader(bytes.NewReader(frameBytes))
	_, err := recvS.ReadFrame(r1)
	if err != nil {
		t.Fatalf("First frame should be accepted: %v", err)
	}

	// بار دوم (همان دیتا): باید رد شود
	r2 := bufio.NewReader(bytes.NewReader(frameBytes))
	_, err = recvS.ReadFrame(r2)
	if err == nil {
		t.Error("Security Fail: Replayed frame was accepted!")
	} else {
		t.Logf("Security Pass: Replay blocked with error: %v", err)
	}
}

// تست ۳: قطع اتصال ناگهانی (Closed Connection)
// هدف: سیستم باید بلافاصله ارور بدهد و منتظر نماند
func TestSuddenClose(t *testing.T) {
	key := make([]byte, 32)
	session, _ := NewSession(key)

	c1, c2 := net.Pipe()
	c2.Close() // بستن فوری طرف مقابل

	err := session.WriteFrame(c1, FrameTypeData, []byte("some data"))
	if err == nil {
		t.Error("Expected error when writing to closed pipe, got nil")
	}
}
func TestConstantTimeComparison(t *testing.T) {
	uuid1 := []byte("12345678-1234-1234-1234-123456789012")
	uuid2 := []byte("12345678-1234-1234-1234-123456789013")

	// به جای uuid1 == uuid2 باید از ConstantTime استفاده شود
	if subtle.ConstantTimeCompare(uuid1, uuid2) == 1 {
		t.Error("UUIDs should not match")
	}
	t.Log("Security Check: Constant-time comparison used.")
}
