package reflex

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

const (
	FrameTypeData  byte = 0x01
	FrameTypeClose byte = 0x0F
)

type Frame struct {
	Type    byte
	Payload []byte
}

type Session struct {
	encryptor cipher.AEAD
	decryptor cipher.AEAD
}

func NewSession(key []byte) (*Session, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Session{
		encryptor: aesgcm,
		decryptor: aesgcm,
	}, nil
}

func (s *Session) WriteFrame(w io.Writer, fType byte, payload []byte) error {
	nonce := make([]byte, 12) // در نسخه نهایی باید رندوم باشد
	ciphertext := s.encryptor.Seal(nil, nonce, payload, []byte{fType})
	header := make([]byte, 3)
	header[0] = fType
	binary.BigEndian.PutUint16(header[1:], uint16(len(ciphertext)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(ciphertext)
	return err
}

func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	fType := header[0]
	length := binary.BigEndian.Uint16(header[1:])
	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	payload, err := s.decryptor.Open(nil, nonce, ciphertext, []byte{fType})
	if err != nil {
		return nil, errors.New("failed to decrypt")
	}
	return &Frame{Type: fType, Payload: payload}, nil
}
