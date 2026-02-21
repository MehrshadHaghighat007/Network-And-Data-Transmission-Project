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

// ۱. اصلاح ساختار FakeConn برای مطابقت با اینترفیس Xray
type FakeConn struct {
	net.Conn
}

// این متدها برای ارضای اینترفیس stat.Connection لازم است
func (f *FakeConn) ByteCountReader() io.Reader { return f.Conn }
func (f *FakeConn) ByteCountWriter() io.Writer { return f.Conn }

func TestFullReflexConnection(t *testing.T) {
	handler := &inbound.Handler{}
	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		defer clientConn.Close()

		// ۲. ارسال Magic (مطمئن شو در کد اصلی ReflexMagic با R بزرگ است)
		magic := make([]byte, 4)
		// اگر هنوز ارور داد، موقتاً به جای reflex.ReflexMagic عدد 0x52464C58 را بگذار
		binary.BigEndian.PutUint32(magic, 0x52464C58)
		_, _ = clientConn.Write(magic)

		cPriv, cPub, _ := reflex.GenerateKeyPair()
		_, _ = clientConn.Write(cPub[:])

		var sPub [32]byte
		io.ReadFull(clientConn, sPub[:])

		// ۳. اصلاح ارور آرایه به اسلایس با استفاده از [:]
		shared := reflex.DeriveSharedKey(cPriv, sPub[:])
		sKey := reflex.DeriveSessionKey(shared, make([]byte, 16))
		session, _ := reflex.NewSession(sKey)

		_ = session.WriteFrame(clientConn, 1, []byte{0x01, 127, 0, 0, 1, 0, 80})
	}()

	// ۴. اصلاح نحوه استفاده از FakeConn
	var fake net.Conn = &FakeConn{Conn: serverConn}

	// حالا کست کردن به stat.Connection روی یک اینترفیس انجام می‌شود
	err := handler.Process(ctx, corenet.Network_TCP, fake.(stat.Connection), nil)

	if err != nil {
		t.Logf("Process ended: %v", err)
	}
}
