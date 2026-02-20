package outbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Outbound struct {
	server *protocol.ServerSpec
}

func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	destination := o.server.Destination

	var conn net.Conn
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

func (o *Outbound) handleHandshake(ctx context.Context, conn net.Conn, link *transport.Link) error {
	magicBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(magicBuf, 0x5246584C)
	if _, err := conn.Write(magicBuf); err != nil {
		return err
	}

	clientPriv, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return err
	}
	if _, err := conn.Write(clientPub[:]); err != nil {
		return err
	}

	serverPubRaw := make([]byte, 32)
	if _, err := io.ReadFull(conn, serverPubRaw); err != nil {
		return err
	}
	var serverPub [32]byte
	copy(serverPub[:], serverPubRaw)

	sharedKey := reflex.DeriveSharedKey(clientPriv, serverPub)
	sessionKey := reflex.DeriveSessionKey(sharedKey, make([]byte, 16))
	rs, err := reflex.NewSession(sessionKey)
	if err != nil {
		return err
	}

	return o.relay(ctx, rs, conn, link)
}

func (o *Outbound) relay(ctx context.Context, rs *reflex.Session, conn net.Conn, link *transport.Link) error {
	dest := o.server.Destination

	// تبدیل مستقیم به byte طبق معماری v1.25+
	addrPayload := []byte{byte(dest.Address.Family())}

	addrPayload = append(addrPayload, dest.Address.IP()...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(dest.Port))
	addrPayload = append(addrPayload, portBuf...)

	// ارسال فریم اول حاوی آدرس مقصد
	if err := rs.WriteFrame(conn, reflex.FrameTypeData, addrPayload); err != nil {
		return err
	}

	req := func() error {
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			for _, b := range mb {
				// ارسال داده‌های کلاینت به سرور
				if err := rs.WriteFrame(conn, reflex.FrameTypeData, b.Bytes()); err != nil {
					b.Release()
					return err
				}
				b.Release()
			}
		}
	}

	resp := func() error {
		reader := bufio.NewReader(conn)
		for {
			frame, err := rs.ReadFrame(reader)
			if err != nil {
				return err
			}
			// دریافت داده‌ها از سرور و فرستادن به کلاینت
			if frame.Type == reflex.FrameTypeData {
				b := buf.New()
				b.Write(frame.Payload)
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					return err
				}
			}
		}
	}

	return task.Run(ctx, req, resp)
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		c := config.(*reflex.OutboundConfig)
		dest := net.TCPDestination(net.ParseAddress(c.Address), net.Port(c.Port))
		return &Outbound{
			server: &protocol.ServerSpec{Destination: dest},
		}, nil
	}))
}
