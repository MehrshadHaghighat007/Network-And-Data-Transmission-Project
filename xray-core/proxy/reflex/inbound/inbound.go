package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const ReflexMagic = 0x5246584C

type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}

type FallbackConfig struct {
	Dest uint32
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)
	peeked, err := reader.Peek(4)
	if err != nil {
		return err
	}

	if binary.BigEndian.Uint32(peeked) == ReflexMagic {
		reader.Discard(4)
		return h.handleHandshake(ctx, reader, conn, dispatcher)
	}

	return h.handleFallback(ctx, reader, conn)
}

func (h *Handler) handleHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// 1. خواندن کلید عمومی کلاینت
	clientPubSlice := make([]byte, 32)
	if _, err := io.ReadFull(reader, clientPubSlice); err != nil {
		h.sendSafeForbiddenResponse(conn)
		return errors.New("failed to read client public key")
	}
	var clientPubArray [32]byte
	copy(clientPubArray[:], clientPubSlice)

	// 2. تولید کلیدهای سرور و ارسال کلید عمومی به کلاینت
	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		h.sendSafeForbiddenResponse(conn)
		return err
	}
	if _, err := conn.Write(serverPub[:]); err != nil {
		h.sendSafeForbiddenResponse(conn)
		return err
	}

	// 3. تولید کلیدهای سشن (Session Key Derivation)
	sharedKey := reflex.DeriveSharedKey(serverPriv, clientPubArray)
	sessionKey := reflex.DeriveSessionKey(sharedKey, make([]byte, 16))

	rs, err := reflex.NewSession(sessionKey)
	if err != nil {
		h.sendSafeForbiddenResponse(conn)
		return err
	}

	// 4. خواندن اولین فریم رمزنگاری شده (حاوی آدرس مقصد)
	frame, err := rs.ReadFrame(reader)
	if err != nil {
		h.sendSafeForbiddenResponse(conn) // اگر رمزگشایی شکست بخورد، یعنی کلیدها اشتباهند
		return errors.New("failed to read/decrypt address frame")
	}

	// 5. اعتبارسنجی طول پلود برای جلوگیری از خطای ایندکس (Index out of range)
	if len(frame.Payload) < 4 {
		h.sendSafeForbiddenResponse(conn)
		return errors.New("invalid address payload size")
	}

	// 6. استخراج پروتکل، آدرس و پورت از فریم
	// Payload[0] معمولاً نوع آدرس است (IPv4/Domain)
	addr := net.IPAddress(frame.Payload[1 : len(frame.Payload)-2])
	port := binary.BigEndian.Uint16(frame.Payload[len(frame.Payload)-2:])
	dest := net.TCPDestination(addr, net.Port(port))

	if !dest.IsValid() {
		h.sendSafeForbiddenResponse(conn)
		return errors.New("destination is not valid")
	}

	// 7. هدایت به مرحله برقراری ارتباط (Relay)
	return h.handleSession(ctx, reader, conn, dispatcher, rs, dest)
}

// تابع کمکی برای ارسال پاسخ فیک 403 جهت فریب سیستم‌های فیلترینگ

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, rs *reflex.Session, dest net.Destination) error {
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "reflex-inbound"})

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	requestDone := func() error {
		for {
			frame, err := rs.ReadFrame(reader)
			if err != nil {
				return err
			}
			if frame.Type == reflex.FrameTypeData {
				b := buf.New()
				b.Write(frame.Payload)
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					return err
				}
			} else if frame.Type == reflex.FrameTypeClose {
				return nil
			}
		}
	}

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
		return errors.New("no fallback destination")
	}
	target, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest))
	if err != nil {
		return err
	}
	defer target.Close()
	go io.Copy(target, reader)
	io.Copy(conn, target)
	return nil
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

func (h *Handler) sendSafeForbiddenResponse(conn stat.Connection) {
	// یک پاسخ HTTP 403 استاندارد که شبیه به سرور Nginx است
	forbidden := "HTTP/1.1 403 Forbidden\r\n" +
		"Server: nginx\r\n" +
		"Date: " + net.IPAddress([]byte{0, 0, 0, 0}).String() + "\r\n" + // یا هر فرمت زمانی دیگر
		"Content-Type: text/html\r\n" +
		"Content-Length: 153\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		"<html>\r\n<head><title>403 Forbidden</title></head>\r\n" +
		"<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n" +
		"<hr><center>nginx</center>\r\n</body>\r\n</html>"

	conn.Write([]byte(forbidden))
}
