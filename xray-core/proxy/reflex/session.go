package reflex

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session مدیریت رمزنگاری و شکل‌دهی ترافیک (Traffic Morphing) را بر عهده دارد
type Session struct {
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
	// Profile برای فعال‌سازی Traffic Morphing (مثلاً YouTube یا Zoom)
	Profile *TrafficProfile
}

// NewSession یک سشن جدید با کلید ۳۲ بایتی چاچا۲۰ ایجاد می‌کند
func NewSession(sessionKey []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}
	return &Session{
		aead:       aead,
		readNonce:  0,
		writeNonce: 0,
	}, nil
}

func (s *Session) getNonce(counter uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// WriteFrame دیتای اصلی را می‌گیرد، در صورت فعال بودن پروفایل به آن پدینگ و تاخیر می‌زند و ارسال می‌کند
func (s *Session) WriteFrame(w io.Writer, fType byte, payload []byte) error {
	var morphedData []byte

	// اعمال Traffic Morphing فقط روی فریم‌های دیتا
	if s.Profile != nil && fType == FrameTypeData {
		targetSize := s.Profile.GetPacketSize()

		// ساختار بسته داخل لایه رمزنگاری: [2 bytes Actual Length] + [Data] + [Random Padding]
		morphedData = make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(morphedData[0:2], uint16(len(payload)))
		copy(morphedData[2:], payload)

		// اضافه کردن پدینگ تصادفی تا رسیدن به سایز هدف (Target Size)
		if len(morphedData) < targetSize {
			paddingLen := targetSize - len(morphedData)
			padding := make([]byte, paddingLen)
			if _, err := rand.Read(padding); err != nil {
				return err
			}
			morphedData = append(morphedData, padding...)
		}
	} else {
		// برای بقیه فریم‌ها (مثل هندشیک یا کنترل) پدینگ اضافه نمی‌شود
		morphedData = payload
	}

	// رمزنگاری کل بسته
	nonce := s.getNonce(s.writeNonce)
	s.writeNonce++
	ciphertext := s.aead.Seal(nil, nonce, morphedData, nil)

	// هدر فریم: [2 bytes ciphertext length] + [1 byte type]
	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(ciphertext)))
	header[2] = fType

	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(ciphertext); err != nil {
		return err
	}

	// اعمال تأخیر زمانی آماری (Timing Obfuscation)
	if s.Profile != nil && fType == FrameTypeData {
		time.Sleep(s.Profile.GetDelay())
	}

	return nil
}

// ReadFrame فریم را می‌خواند، رمزگشایی می‌کند و دیتای واقعی را از میان پدینگ استخراج می‌کند
func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
	// خواندن هدر ۳ بایتی
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(header[0:2])
	fType := header[2]

	// خواندن بدنه رمزنگاری شده
	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, err
	}

	// رمزگشایی
	nonce := s.getNonce(s.readNonce)
	s.readNonce++
	payload, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// استخراج دیتای واقعی اگر Morphing فعال بود
	if s.Profile != nil && fType == FrameTypeData {
		if len(payload) < 2 {
			return nil, errors.New("morphed frame too short")
		}
		actualLen := binary.BigEndian.Uint16(payload[0:2])
		if int(actualLen)+2 > len(payload) {
			return nil, errors.New("morphed frame actual length mismatch")
		}
		return &Frame{Type: fType, Payload: payload[2 : 2+actualLen]}, nil
	}

	return &Frame{Type: fType, Payload: payload}, nil
}

// HandleControlFrame برای پردازش دستورات داینامیک از طرف مقابل (مثلاً تغییر پدینگ در لحظه)
func (s *Session) HandleControlFrame(f *Frame) {
	if s.Profile == nil || len(f.Payload) < 4 {
		return
	}

	value := binary.BigEndian.Uint32(f.Payload)

	switch f.Type {
	case FrameTypePadding:
		// تنظیم سایز بسته بعدی (Override موقت)
		s.Profile.SetNextPacketSize(int(value))

	case FrameTypeTiming:
		// تنظیم تاخیر بسته بعدی (بر حسب میلی‌ثانیه)
		s.Profile.SetNextDelay(time.Duration(value) * time.Millisecond)
	}
}
