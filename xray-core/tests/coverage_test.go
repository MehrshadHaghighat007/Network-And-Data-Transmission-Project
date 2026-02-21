package tests

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestComprehensiveCoverage(t *testing.T) {
	priv, pub, _ := reflex.GenerateKeyPair()
	shared := reflex.DeriveSharedKey(priv, pub)
	_ = reflex.DeriveSessionKey(shared, make([]byte, 16))

	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sendS, _ := reflex.NewSession(key)
	recvS, _ := reflex.NewSession(key)

	p := &reflex.YouTubeProfile
	sendS.Profile = p
	recvS.Profile = p

	data := make([]byte, 50)
	var buf bytes.Buffer
	_ = sendS.WriteFrame(&buf, reflex.FrameTypeData, data)
	_, _ = recvS.ReadFrame(&buf)

	_ = sendS.Profile.GetPacketSize()
	_ = sendS.Profile.GetDelay()
	sendS.Profile.SetNextPacketSize(1200)
	sendS.Profile.SetNextDelay(time.Millisecond * 1)

	cf := &reflex.Frame{Type: reflex.FrameTypePadding, Payload: []byte{0, 0, 0, 100}}
	sendS.HandleControlFrame(cf)

	tf := &reflex.Frame{Type: reflex.FrameTypeTiming, Payload: []byte{0, 0, 0, 10}}
	sendS.HandleControlFrame(tf)
}
