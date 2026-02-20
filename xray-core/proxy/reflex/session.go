package reflex

import (
	"crypto/cipher"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type Session struct {
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
}

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

func (s *Session) WriteFrame(w io.Writer, fType byte, payload []byte) error {
	nonce := s.getNonce(s.writeNonce)
	s.writeNonce++
	ciphertext := s.aead.Seal(nil, nonce, payload, nil)

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(ciphertext)))
	header[2] = fType

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
	length := binary.BigEndian.Uint16(header[0:2])
	fType := header[2]

	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, err
	}

	nonce := s.getNonce(s.readNonce)
	s.readNonce++
	payload, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return &Frame{Type: fType, Payload: payload}, nil
}
