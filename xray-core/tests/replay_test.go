package tests

import (
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestReplayProtection(t *testing.T) {
	testKey := make([]byte, 32)
	session, _ := reflex.NewSession(testKey)

	frame, _ := session.CreateFrame(reflex.FrameTypeData, []byte("test"))

	err1 := session.ProcessFrame(frame)
	if err1 != nil {
		t.Errorf("First frame failed: %v", err1)
	}

	err2 := session.ProcessFrame(frame)
	if err2 == nil {
		t.Fatal("Security Error: Replay accepted!")
	}
}
