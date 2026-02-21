package reflex

import (
	"testing"
)

func TestReplayProtection(t *testing.T) {
	// ۱. آماده‌سازی کلید و سشن تستی
	testKey := make([]byte, 32) // یک کلید تستی ۳۲ بایتی
	session, err := NewSession(testKey)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// ۲. ساخت یک فریم تستی
	// فرض می‌کنیم پروتکل تو برای هر فریم یک شماره ترتیب (Sequence Number) دارد
	payload := []byte("test data")
	frame, err := session.CreateFrame(FrameTypeData, payload)
	if err != nil {
		t.Fatalf("failed to create frame: %v", err)
	}

	// ۳. ارسال اول - باید موفق باشد
	t.Log("Sending first frame...")
	err1 := session.ProcessFrame(frame)
	if err1 != nil {
		t.Errorf("First frame should succeed, but got: %v", err1)
	}

	// ۴. ارسال دوباره همان فریم (Replay) - باید رد (Reject) شود
	t.Log("Sending the same frame again (Replay attack)...")
	err2 := session.ProcessFrame(frame)

	if err2 == nil {
		t.Fatal("CRITICAL SECURITY ERROR: Replay frame was accepted! It should have been rejected.")
	} else {
		t.Logf("Success: Replay was correctly rejected with error: %v", err2)
	}
}
