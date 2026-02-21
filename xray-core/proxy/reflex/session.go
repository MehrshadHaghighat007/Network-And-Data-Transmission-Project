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

// Session represents a secure Reflex connection state.
// It handles AEAD encryption/decryption, nonce management for replay protection,
// and traffic shaping (morphing) based on the assigned TrafficProfile.
type Session struct {
	AEAD       cipher.AEAD // ۱. تغییر از aead به AEAD برای دسترسی در تست‌ها
	readNonce  uint64
	writeNonce uint64
	Profile    *TrafficProfile
}

// NewSession creates a new Reflex session with the given 32-byte session key.
// It initializes the ChaCha20-Poly1305 AEAD cipher.
// Returns an error if the key length is incorrect.
func NewSession(sessionKey []byte) (*Session, error) {
	aeadInst, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}
	return &Session{
		AEAD:       aeadInst, // ۲. مقداردهی فیلد جدید AEAD
		readNonce:  0,
		writeNonce: 0,
	}, nil
}

// getNonce generates a 12-byte nonce for AEAD operations using an 8-byte counter.
func (s *Session) getNonce(counter uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// CreateFrame encapsulates the payload into an encrypted Reflex frame format.
func (s *Session) CreateFrame(fType byte, payload []byte) ([]byte, error) {
	nonce := s.getNonce(s.writeNonce)
	s.writeNonce++
	// استفاده از فیلد بزرگ AEAD
	ciphertext := s.AEAD.Seal(nil, nonce, payload, nil)

	frame := make([]byte, 3+len(ciphertext))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(ciphertext)))
	frame[2] = fType
	copy(frame[3:], ciphertext)
	return frame, nil
}

// ProcessFrame validates and decrypts an in-memory frame.
func (s *Session) ProcessFrame(frameData []byte) error {
	if len(frameData) < 3 {
		return errors.New("frame too short")
	}
	length := binary.BigEndian.Uint16(frameData[0:2])
	if len(frameData) < int(3+length) {
		return errors.New("incomplete frame")
	}
	ciphertext := frameData[3 : 3+length]
	nonce := s.getNonce(s.readNonce)

	// استفاده از فیلد بزرگ AEAD
	_, err := s.AEAD.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return errors.New("replay attack detected or invalid frame")
	}
	s.readNonce++
	return nil
}

// WriteFrame encrypts and writes a frame to the provided io.Writer.
func (s *Session) WriteFrame(w io.Writer, fType byte, payload []byte) error {
	var morphedData []byte
	if s.Profile != nil && fType == FrameTypeData {
		targetSize := s.Profile.GetPacketSize()
		morphedData = make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(morphedData[0:2], uint16(len(payload)))
		copy(morphedData[2:], payload)

		if len(morphedData) < targetSize {
			paddingLen := targetSize - len(morphedData)
			padding := make([]byte, paddingLen)
			_, _ = rand.Read(padding)
			morphedData = append(morphedData, padding...)
		}
	} else {
		morphedData = payload
	}

	nonce := s.getNonce(s.writeNonce)
	s.writeNonce++

	// استفاده از فیلد بزرگ AEAD
	ciphertext := s.AEAD.Seal(nil, nonce, morphedData, nil)
	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(ciphertext)))
	header[2] = fType

	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(ciphertext); err != nil {
		return err
	}
	if s.Profile != nil && fType == FrameTypeData {
		time.Sleep(s.Profile.GetDelay())
	}
	return nil
}

// ReadFrame reads, decrypts, and un-morphs a Reflex frame from the io.Reader.
func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(header[0:2])
	fType := header[2]

	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, err
	}

	nonce := s.getNonce(s.readNonce)
	s.readNonce++

	// استفاده از فیلد بزرگ AEAD
	payload, err := s.AEAD.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	if s.Profile != nil && fType == FrameTypeData {
		if len(payload) < 2 {
			return nil, errors.New("morphed frame too short")
		}
		actualLen := binary.BigEndian.Uint16(payload[0:2])
		if int(actualLen) > len(payload)-2 {
			return nil, errors.New("invalid morphed payload length")
		}
		return &Frame{Type: fType, Payload: payload[2 : 2+actualLen]}, nil
	}
	return &Frame{Type: fType, Payload: payload}, nil
}

// HandleControlFrame processes protocol-level control frames (Padding/Timing).
func (s *Session) HandleControlFrame(f *Frame) {
	if s.Profile == nil || len(f.Payload) < 4 {
		return
	}
	value := binary.BigEndian.Uint32(f.Payload)
	switch f.Type {
	case FrameTypePadding:
		s.Profile.SetNextPacketSize(int(value))
	case FrameTypeTiming:
		s.Profile.SetNextDelay(time.Duration(value) * time.Millisecond)
	}
}
