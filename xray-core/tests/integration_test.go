package tests

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestIntegrationFull(t *testing.T) {
	handler := &inbound.Handler{}
	clientConn, serverConn := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		defer clientConn.Close()

		// ۱. حل مشکل ReflexMagic:
		// اگر در پکیج reflex اکسپورت نشده، مستقیم از مقدارش استفاده می‌کنیم
		magic := make([]byte, 4)
		binary.BigEndian.PutUint32(magic, 0x52464C58) // مقدار استاندارد Reflex
		_, _ = clientConn.Write(magic)

		cPriv, cPub, _ := reflex.GenerateKeyPair()
		_, _ = clientConn.Write(cPub[:])

		receivedServerPub := make([]byte, 32)
		if _, err := io.ReadFull(clientConn, receivedServerPub); err != nil {
			return
		}

		// ۲. حل مشکل آرایه به اسلایس برای DeriveSharedKey
		sharedKey := reflex.DeriveSharedKey(cPriv, receivedServerPub[:])
		sessionKey := reflex.DeriveSessionKey(sharedKey, make([]byte, 16))
		clientSession, _ := reflex.NewSession(sessionKey)

		addrBuffer := []byte{0x01, 127, 0, 0, 1, 0, 80}
		_ = clientSession.WriteFrame(clientConn, reflex.FrameTypeData, addrBuffer)
	}()

	// ۳. حل مشکل FakeConn:
	// تعریف متغیر به صورت net.Conn تا اجازه Type Assertion به stat.Connection را بدهد
	var conn net.Conn = &FakeConn{Conn: serverConn}

	// حالا بدون ارور "not an interface" کست می‌شود
	err := handler.Process(ctx, corenet.Network_TCP, conn.(stat.Connection), nil)

	if err != nil {
		t.Logf("Integration test finished: %v", err)
	}
}
