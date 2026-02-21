package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const ReflexMagic = 0x5246584C

// تابع ساخت خطا
func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}

type Handler struct {
	fallback   *FallbackConfig
	dispatcher routing.Dispatcher
}

type FallbackConfig struct {
	Dest uint32
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// در فایل inbound.go
func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	h.dispatcher = dispatcher

	reader := bufio.NewReader(conn)
	peeked, err := reader.Peek(4)
	if err != nil {
		conn.Close() // حتماً ببند
		return err
	}

	if binary.BigEndian.Uint32(peeked) == ReflexMagic {
 reader.Discard(4)	
	err := h.handleHandshake(ctx, reader, conn)
		if err != nil {
			conn.Close() // اگر هندشیک شکست خورد ببند
		}
		return err
	}

	return h.handleFallback(ctx, reader, conn)
}
func (h *Handler) handleHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	clientPubSlice := make([]byte, 32)
	if _, err := io.ReadFull(reader, clientPubSlice); err != nil {
		h.sendSafeForbiddenResponse(conn)
		return newError("failed to read client public key").Base(err)
	}
	var clientPubArray [32]byte
	copy(clientPubArray[:], clientPubSlice)

	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		h.sendSafeForbiddenResponse(conn)
		return err
	}
	if _, err := conn.Write(serverPub[:]); err != nil {
		h.sendSafeForbiddenResponse(conn)
		return err
	}

	sharedKey := reflex.DeriveSharedKey(serverPriv, clientPubArray[:])
	sessionKey := reflex.DeriveSessionKey(sharedKey, make([]byte, 16))

	rs, err := reflex.NewSession(sessionKey)
	if err != nil {
		h.sendSafeForbiddenResponse(conn)
		return err
	}

p := &reflex.YouTubeProfile
	rs.Profile = p

	frame, err := rs.ReadFrame(reader)
	if err != nil {
		h.sendSafeForbiddenResponse(conn)
		return newError("failed to decrypt address frame").Base(err)
	}

	if len(frame.Payload) < 4 {
		h.sendSafeForbiddenResponse(conn)
		return newError("invalid address payload")
	}

	// استخراج آدرس مقصد از فریم
	addr := net.IPAddress(frame.Payload[1 : len(frame.Payload)-2])
	port := binary.BigEndian.Uint16(frame.Payload[len(frame.Payload)-2:])
	dest := net.TCPDestination(addr, net.Port(port))

	if !dest.IsValid() {
		h.sendSafeForbiddenResponse(conn)
		return newError("invalid destination")
	}

	return h.handleSession(ctx, reader, conn, rs, dest)
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, rs *reflex.Session, dest net.Destination) error {
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "reflex-inbound"})

	if h.dispatcher == nil {
		return newError("Dispatcher is nil")
	}

	link, err := h.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return newError("failed to dispatch request").Base(err)
	}

	// کلاینت -> مقصد
	requestDone := func() error {
		for {
			frame, err := rs.ReadFrame(reader)
			if err != nil {
				return err
			}

			switch frame.Type {
			case reflex.FrameTypeData:
				b := buf.New()
				_, _ = b.Write(frame.Payload)
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					return err
				}
			case reflex.FrameTypePadding, reflex.FrameTypeTiming:
				rs.HandleControlFrame(frame)
			case reflex.FrameTypeClose:
				return nil
			}
		}
	}

	// مقصد -> کلاینت
	responseDone := func() error {
		for {
			multiBuffer, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			for _, b := range multiBuffer {
				if err := rs.WriteFrame(conn, reflex.FrameTypeData, b.Bytes()); err != nil {
					b.Release()
					return err
				}
				b.Release()
			}
		}
	}

	return task.Run(ctx, requestDone, responseDone)
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		return newError("no fallback destination")
	}

	dest := net.TCPDestination(net.LocalHostIP, net.Port(h.fallback.Dest))

	// اصلاح شده: استفاده از Dial ساده بدون DialerOptions که در نسخه‌های جدید حذف شده
	target, err := internet.Dial(ctx, dest, nil)
	if err != nil {
		return err
	}
	defer target.Close()

	return task.Run(ctx, func() error {
		_, err := io.Copy(target, reader)
		return err
	}, func() error {
		_, err := io.Copy(conn, target)
		return err
	})
}

func (h *Handler) sendSafeForbiddenResponse(conn stat.Connection) {
	forbidden := fmt.Sprintf(
		"HTTP/1.1 403 Forbidden\r\n"+
			"Server: nginx\r\n"+
			"Date: %s\r\n"+
			"Content-Type: text/html\r\n"+
			"Content-Length: 153\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"<html>\r\n<head><title>403 Forbidden</title></head>\r\n"+
			"<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n"+
			"<hr><center>nginx</center>\r\n</body>\r\n</html>",
		time.Now().Format(time.RFC1123),
	)
	_, _ = conn.Write([]byte(forbidden))








	
	conn.Close()
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		c := config.(*reflex.InboundConfig)
		handler := &Handler{}
		if c.Fallback != nil {
			handler.fallback = &FallbackConfig{Dest: c.Fallback.Dest}
		}
		return handler, nil
	}))
}
