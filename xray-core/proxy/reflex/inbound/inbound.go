package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

const ReflexMagic = 0x5246584C

type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}

type MemoryAccount struct {
	Id string
}

func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	return ok && a.Id == reflexAccount.Id
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{Id: a.Id}
}

type FallbackConfig struct {
	Dest uint32
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) isReflexProtocol(reader *bufio.Reader) (bool, string) {
	peeked, err := reader.Peek(64)
	if err != nil {
		return false, ""
	}
	if len(peeked) >= 4 && binary.BigEndian.Uint32(peeked[0:4]) == ReflexMagic {
		return true, "MAGIC"
	}
	if bytes.HasPrefix(peeked, []byte("POST /api/v1/endpoint")) {
		return true, "HTTP"
	}
	return false, ""
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)
	isReflex, mode := h.isReflexProtocol(reader)

	if !isReflex {
		return h.handleFallback(ctx, reader, conn)
	}

	if mode == "MAGIC" {
		return h.handleMagicHandshake(ctx, reader, conn, dispatcher)
	}
	return h.handleHTTPHandshake(ctx, reader, conn, dispatcher)
}

// --- بخش هندشیک و احراز هویت ---

func (h *Handler) handleHTTPHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// ۱. خواندن درخواست کلاینت (ساده شده)
	// در محیط واقعی باید Headerها را پارس کنید تا به Body برسید
	line, _ := reader.ReadString('\n') // Skip Request Line
	for {
		line, _ = reader.ReadString('\n')
		if line == "\r\n" || line == "\n" || line == "" {
			break
		}
	}

	var body struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(reader).Decode(&body); err != nil {
		return err
	}

	rawHandshake, err := base64.StdEncoding.DecodeString(body.Data)
	if err != nil {
		return err
	}

	var clientHS reflex.ClientHandshake
	if err := json.Unmarshal(rawHandshake, &clientHS); err != nil {
		return err
	}

	return h.processHandshake(ctx, reader, conn, dispatcher, clientHS)
}

func (h *Handler) processHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, clientHS reflex.ClientHandshake) error {
	// ۱. احراز هویت کاربر با UUID
	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// ۲. تولید کلیدهای سرور و محاسبه کلید مشترک
	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return err
	}

	sharedKey := reflex.DeriveSharedKey(serverPriv, clientHS.PublicKey)
	sessionKey := reflex.DeriveSessionKey(sharedKey, clientHS.Nonce[:])

	// ۳. ارسال پاسخ HTTP 200 به کلاینت (شبیه‌سازی API)
	serverHS := reflex.ServerHandshake{
		PublicKey: serverPub,
		Status:    "ok",
	}
	hsBytes, _ := json.Marshal(serverHS)

	response := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
	conn.Write([]byte(response))
	conn.Write(hsBytes)

	// ۴. ورود به مرحله انتقال دیتا
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	u := uuid.UUID(userID).String()
	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == u {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, user *protocol.MemoryUser) error {
	// ۱. ایجاد یک جلسه (Session) جدید برای مدیریت رمزنگاری فریم‌ها
	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		return err
	}

	// حلقه اصلی برای خواندن فریم‌ها تا زمانی که اتصال باز است
	for {
		// ۲. خواندن و رمزگشایی فریم بعدی
		frame, err := session.ReadFrame(reader)
		if err != nil {
			if err == io.EOF {
				return nil // اتصال به صورت عادی بسته شد
			}
			return err
		}

		// ۳. تصمیم‌گیری بر اساس نوع فریم (Switch Case)
		switch frame.Type {
		case reflex.FrameTypeData:
			// فریم حاوی داده‌های واقعی کاربر است
			// در اینجا باید داده را به مقصد (Upstream) بفرستیم
			if err := h.handleData(ctx, frame.Payload, conn, dispatcher, session, user); err != nil {
				return err
			}

		case reflex.FrameTypePadding:
			// داده‌های پوچ برای مقابله با تحلیل ترافیک؛ نادیده می‌گیریم
			continue

		case reflex.FrameTypeTiming:
			// بسته‌های کنترل تاخیر؛ نادیده می‌گیریم
			continue

		case reflex.FrameTypeClose:
			// کلاینت درخواست بستن اتصال را داده است
			return nil

		default:
			return errors.New("unknown frame type received")
		}
	}
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	// در صورت عدم شناسایی، اتصال را به مقصد تعیین شده در کانفیگ هدایت کن (یا ببند)
	return conn.Close()
}

func (h *Handler) handleMagicHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// پیاده‌سازی مشابه HTTP اما بدون Headerها
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0),
	}
	// اگر در proto فیلد Email ندارید، از خود Id استفاده کنید
	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.Id, // تغییر از client.Email به client.Id
			Account: &MemoryAccount{Id: client.Id},
		})
	}
	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{Dest: config.Fallback.Dest}
	}
	return handler, nil
}

func (h *Handler) handleData(ctx context.Context, data []byte, conn stat.Connection, dispatcher routing.Dispatcher, session *reflex.Session, user *protocol.MemoryUser) error {
	// ۱. استخراج مقصد (Destination)
	// نکته: در پروتکل واقعی، آدرس مقصد باید در اولین پکت دیتا توسط کلاینت فرستاده شود.
	// فعلاً برای تست از یک آدرس ثابت استفاده می‌کنیم:
	dest := net.TCPDestination(net.ParseAddress("1.1.1.1"), net.Port(80))

	// ۲. ارسال درخواست به Dispatcher برای باز کردن مسیر به اینترنت
	sessionCtx := protocol.ContextWithUser(ctx, user)
	link, err := dispatcher.Dispatch(sessionCtx, dest)
	if err != nil {
		return err
	}

	// ۳. ارسال اولین تکه داده (که همین الان دریافت کردیم) به Upstream
	initialBuffer := buf.FromBytes(data)
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{initialBuffer}); err != nil {
		return err
	}

	// ۴. مدیریت ترافیک برگشتی (از اینترنت به کلاینت) در یک Goroutine جداگانه
	go func() {
		defer link.Writer.Close()
		for {
			// خواندن داده از Upstream
			multiBuffer, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				break
			}

			// تبدیل داده‌ها به فریم‌های رمزنگاری شده و ارسال به کلاینت
			for _, b := range multiBuffer {
				if err := session.WriteFrame(conn, reflex.FrameTypeData, b.Bytes()); err != nil {
					b.Release()
					return
				}
				b.Release()
			}
		}
	}()

	return nil
}
