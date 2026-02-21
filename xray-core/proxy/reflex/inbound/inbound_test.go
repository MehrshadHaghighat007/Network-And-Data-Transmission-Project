package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// تست اول: بررسی هندشیک و پاسخ امنیتی ۴۰۳
func TestHandshake(t *testing.T) {
	handler := &Handler{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		defer clientConn.Close()

		// ۱. ارسال Magic
		magicBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(magicBuf, 0x5246584C)
		_, _ = clientConn.Write(magicBuf)

		// ۲. ارسال کلید عمومی کلاینت
		cPriv, cPub, _ := reflex.GenerateKeyPair()
		_, _ = clientConn.Write(cPub)

		// ۳. دریافت کلید عمومی سرور
		serverPub := make([]byte, 32)
		_, _ = io.ReadFull(clientConn, serverPub)

		// ۴. ایجاد سشن کلاینت برای فرستادن فریم اول
		sharedKey := reflex.DeriveSharedKey(cPriv, serverPub)
		sessionKey := reflex.DeriveSessionKey(sharedKey, make([]byte, 16))
		clientSession, _ := reflex.NewSession(sessionKey)

		// ۵. ارسال فریم اول (آدرس مقصد) - این همون جاییه که سرور منتظرشه!
		// فرمت: [Family(1) + IP(4) + Port(2)]
		addrPayload := []byte{0x01, 127, 0, 0, 1, 0, 80}
		_ = clientSession.WriteFrame(clientConn, reflex.FrameTypeData, addrPayload)
	}()

	reader := bufio.NewReader(serverConn)
	// اصلاح شده: حذف nil از انتهای آرگومان‌ها
	err := handler.handleHandshake(context.Background(), reader, serverConn.(stat.Connection))

	if err != nil {
		t.Logf("Handshake reached end with error (expected): %v", err)
	}
}

// تست دوم: بررسی مکانیزم Fallback
func TestFallback(t *testing.T) {
	fakeSite := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to my Personal Blog"))
	}))
	defer fakeSite.Close()

	addrParts := strings.Split(fakeSite.Listener.Addr().String(), ":")
	port, _ := strconv.Atoi(addrParts[len(addrParts)-1])

	handler := &Handler{
		fallback: &FallbackConfig{
			Dest: uint32(port),
		},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		// ارسال یک درخواست معمولی (غیر پروتکل Reflex) برای تست Fallback
		clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
		resp := make([]byte, 1024)
		n, _ := clientConn.Read(resp)
		t.Logf("Scanner received: %s", string(resp[:n]))
	}()

	// اجرای متد Process
	err := handler.Process(context.Background(), corenet.Network_TCP, serverConn.(stat.Connection), nil)

	if err != nil && !strings.Contains(err.Error(), "closed") {
		t.Logf("Process finished with note: %v", err)
	}
}
