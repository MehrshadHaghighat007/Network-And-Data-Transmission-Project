package outbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	stdnet "net"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport/internet"

	// ایمپورت پکیج مادر برای دسترسی به توابع رمزنگاری و سشن
	"github.com/xtls/xray-core/proxy/reflex"
)

type Outbound struct {
	serverList    *protocol.ServerList
	serverPicker  protocol.ServerPicker
	policyManager policy.Manager
}

func NewOutbound(ctx context.Context, config *reflex.OutboundConfig) (*Outbound, error) {
	serverList := protocol.NewServerList()
	// در نسخه‌های جدید ایکس‌ری، آدرس و پورت مستقیم در پروتباف تعریف شده‌اند
	// اگر از Receiver استفاده نمی‌کنید، مستقیماً از config.Address استفاده می‌کنیم
	dest := net.TCPDestination(net.ParseAddress(config.Address), net.Port(config.Port))
	serverList.AddServer(protocol.NewServerSpec(dest, protocol.BeforeVersion(protocol.DefaultProtocolVersion)))

	return &Outbound{
		serverList:    serverList,
		serverPicker:  protocol.NewRoundRobinServerPicker(serverList),
		policyManager: session.ContextPolicyManager(ctx),
	}, nil
}

func (o *Outbound) Process(ctx context.Context, link *common.Link, dialer internet.Dialer) error {
	outbound := o.serverPicker.PickServer()
	if outbound == nil {
		return errors.New("no available server")
	}
	destination := outbound.Destination()

	var conn stdnet.Conn
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		rawConn, err := dialer.Dial(ctx, destination)
		if err != nil {
			return err
		}
		conn = rawConn
		return nil
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	return o.handleHandshake(ctx, conn, link)
}

func (o *Outbound) handleHandshake(ctx context.Context, conn stdnet.Conn, link *common.Link) error {
	// ۱. ارسال Magic Number
	magicBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(magicBuf, 0x5246584C)
	if _, err := conn.Write(magicBuf); err != nil {
		return err
	}

	// ۲. تولید کلیدهای X25519 از پکیج مادر
	clientPriv, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return err
	}

	// ۳. ارسال کلید عمومی کلاینت
	if _, err := conn.Write(clientPub[:]); err != nil {
		return err
	}

	// ۴. دریافت کلید عمومی سرور
	serverPubRaw := make([]byte, 32)
	if _, err := io.ReadFull(conn, serverPubRaw); err != nil {
		return err
	}
	var serverPub [32]byte
	copy(serverPub[:], serverPubRaw)

	// ۵. تولید کلید نشست
	sharedKey := reflex.DeriveSharedKey(clientPriv, serverPub)
	sessionKey := reflex.DeriveSessionKey(sharedKey, make([]byte, 16))

	// ۶. ایجاد سشن رمزنگاری
	s, err := reflex.NewSession(sessionKey)
	if err != nil {
		return err
	}

	return o.relay(ctx, s, conn, link)
}

func (o *Outbound) relay(ctx context.Context, s *reflex.Session, conn stdnet.Conn, link *common.Link) error {
	// استخراج مقصد نهایی از Context
	ob := session.OutboundFromContext(ctx)
	if ob == nil || !ob.Target.IsValid() {
		return errors.New("target destination not found")
	}
	dest := ob.Target

	// ارسال آدرس مقصد در فریم اول
	addrPayload := []byte{dest.Address.Family().Byte()}
	addrPayload = append(addrPayload, dest.Address.IP()...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(dest.Port))
	addrPayload = append(addrPayload, portBuf...)

	if err := s.WriteFrame(conn, reflex.FrameTypeData, addrPayload); err != nil {
		return err
	}

	readDone := signal.NewDoneStage()
	writeDone := signal.NewDoneStage()

	// App -> Proxy Server
	go func() {
		defer writeDone.Done()
		for {
			multiBuffer, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				break
			}
			for _, b := range multiBuffer {
				if err := s.WriteFrame(conn, reflex.FrameTypeData, b.Bytes()); err != nil {
					b.Release()
					return
				}
				b.Release()
			}
		}
		s.WriteFrame(conn, reflex.FrameTypeClose, nil)
	}()

	// Proxy Server -> App
	go func() {
		defer readDone.Done()
		reader := bufio.NewReader(conn)
		for {
			frame, err := s.ReadFrame(reader)
			if err != nil {
				break
			}
			if frame.Type == reflex.FrameTypeData {
				b := buf.New()
				b.Write(frame.Payload)
				link.Writer.WriteMultiBuffer(buf.MultiBuffer{b})
			} else if frame.Type == reflex.FrameTypeClose {
				break
			}
		}
	}()

	return signal.WaitEmpty(ctx, readDone, writeDone)
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewOutbound(ctx, config.(*reflex.OutboundConfig))
	}))
}
