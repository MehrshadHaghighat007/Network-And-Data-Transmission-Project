package tests

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestEmptyData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := reflex.NewSession(key)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	done := make(chan bool)
	go func() {
		reader := bufio.NewReader(c2)
		_, err := session.ReadFrame(reader)
		if err == nil {
			done <- true
		}
	}()

	err := session.WriteFrame(c1, reflex.FrameTypeData, []byte{})
	if err != nil {
		t.Errorf("Failed to write empty data: %v", err)
	}

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Error("Timeout: Empty data test got stuck")
	}
}

func TestReplayEdgeCase(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	sendS, _ := reflex.NewSession(key)
	recvS, _ := reflex.NewSession(key)

	var b bytes.Buffer
	payload := []byte("replay me")
	_ = sendS.WriteFrame(&b, reflex.FrameTypeData, payload)
	frameBytes := b.Bytes()

	r1 := bufio.NewReader(bytes.NewReader(frameBytes))
	_, err := recvS.ReadFrame(r1)
	if err != nil {
		t.Fatalf("First frame should be accepted: %v", err)
	}

	r2 := bufio.NewReader(bytes.NewReader(frameBytes))
	_, err = recvS.ReadFrame(r2)
	if err == nil {
		t.Error("Security Fail: Replayed frame was accepted!")
	}
}
