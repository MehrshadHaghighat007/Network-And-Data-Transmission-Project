package tests // نام پکیج باید با بقیه فایل‌های این پوشه یکی باشد

import (
	"bytes"
	"fmt"

	"github.com/xtls/xray-core/proxy/reflex" // ایمپورت پکیج اصلی
)

func ExampleNewSession() {
	// استفاده از پیشوند reflex. برای دسترسی به توابع
	sessionKey := make([]byte, 32)
	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if session != nil {
		fmt.Println("Session initialized")
	}
	// Output: Session initialized
}

func ExampleSession_WriteFrame() {
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key)

	var buf bytes.Buffer
	data := []byte("hello reflex")

	// استفاده از reflex. برای دسترسی به ثابت FrameTypeData (یا عدد آن)
	err := session.WriteFrame(&buf, 1, data)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if buf.Len() > 0 {
		fmt.Println("Frame successfully written to buffer")
	}
	// Output: Frame successfully written to buffer
}
