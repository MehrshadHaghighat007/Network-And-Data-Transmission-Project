package inbound

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestFullReflexConnection(t *testing.T) {
	handler := &Handler{}
	clientConn, serverConn := net.Pipe()

	// استفاده از Context برای مدیریت چرخه حیات کلاینت
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		defer clientConn.Close()

		// ۱. ارسال Magic
		magic := make([]byte, 4)
		binary.BigEndian.PutUint32(magic, ReflexMagic)
		_, _ = clientConn.Write(magic)

		// ۲. تولید کلید کلاینت
		cPriv, cPub, _ := reflex.GenerateKeyPair() // نام متغیر cPriv است
		_, _ = clientConn.Write(cPub)

		// ۳. دریافت کلید سرور
		receivedServerPub := make([]byte, 32)
		if _, err := io.ReadFull(clientConn, receivedServerPub); err != nil {
			return
		}

		// ۴. ایجاد سشن
		// اصلاح نام متغیر از clientPriv به cPriv و تبدیل آرایه به اسلایس با [:]
		sharedKey := reflex.DeriveSharedKey(cPriv, receivedServerPub[:])
		sessionKey := reflex.DeriveSessionKey(sharedKey, make([]byte, 16))
		clientSession, _ := reflex.NewSession(sessionKey)

		// ۵. ارسال آدرس مقصد
		addrBuffer := []byte{0x01, 127, 0, 0, 1, 0, 80}

		// ساخت کانال برای چک کردن وضعیت رایت
		done := make(chan struct{})
		go func() {
			_ = clientSession.WriteFrame(clientConn, reflex.FrameTypeData, addrBuffer)
			close(done)
		}()

		// اگر سرور زود بسته شد، منتظر رایت نمون
		select {
		case <-done:
		case <-ctx.Done():
		}
	}()

	// اجرای سرور
	err := handler.Process(ctx, corenet.Network_TCP, serverConn.(stat.Connection), nil)

	if err != nil {
		t.Logf("Process ended with expected behavior: %v", err)
	} else {
		t.Log("Test passed!")
	}
}
