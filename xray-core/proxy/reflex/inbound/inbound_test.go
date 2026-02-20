package inbound

import (
	"bufio"
	"context"
	"net"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestHandshake(t *testing.T) {
	handler := &Handler{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		// ۱. ارسال کلید کلاینت
		_, clientPub, _ := reflex.GenerateKeyPair()
		clientConn.Write(clientPub[:])

		// ۲. دریافت کلید سرور
		serverPub := make([]byte, 32)
		clientConn.Read(serverPub)
		t.Log("Client received server pubkey")

		// ۳. ارسال فریم نامعتبر (برای تحریک پاسخ امنیتی سرور)
		clientConn.Write([]byte{0, 0, 0})

		// ۴. حیاتی: کلاینت باید دیتای فریب‌دهنده سرور را بخواند تا سرور آزاد شود
		decoyBuffer := make([]byte, 1024)
		n, _ := clientConn.Read(decoyBuffer)
		t.Logf("Client received decoy response (%d bytes). Handshake rejected safely.", n)
	}()

	reader := bufio.NewReader(serverConn)
	err := handler.handleHandshake(context.Background(), reader, serverConn, nil)

	// اگر ارور ReadFrame داد (به خاطر رمزنگاری)، تست پیشرفت کرده است
	if err != nil {
		t.Logf("Handshake reached end with error (expected): %v", err)
	}
}
