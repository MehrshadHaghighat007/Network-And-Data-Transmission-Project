package reflex

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestComprehensiveCoverage(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	shared := DeriveSharedKey(priv, pub)
	_ = DeriveSessionKey(shared, make([]byte, 16))

	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sendS, _ := NewSession(key)
	recvS, _ := NewSession(key)

	p := &YouTubeProfile
	sendS.Profile = p
	recvS.Profile = p

	data := make([]byte, 50)
	var buf bytes.Buffer
	_ = sendS.WriteFrame(&buf, FrameTypeData, data)
	_, _ = recvS.ReadFrame(&buf)

	_ = sendS.Profile.GetPacketSize()
	_ = sendS.Profile.GetDelay()
	sendS.Profile.SetNextPacketSize(1200)
	sendS.Profile.SetNextDelay(time.Millisecond * 1)

	cf := &Frame{Type: FrameTypePadding, Payload: []byte{0, 0, 0, 100}}
	sendS.HandleControlFrame(cf)

	tf := &Frame{Type: FrameTypeTiming, Payload: []byte{0, 0, 0, 10}}
	sendS.HandleControlFrame(tf)
}
