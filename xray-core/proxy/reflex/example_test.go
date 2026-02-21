package reflex_test

import (
	"bytes"
	"fmt"

	"github.com/xtls/xray-core/proxy/reflex"
)

func ExampleNewSession() {
	// کلید باید ۳۲ بایت باشد
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

	// به جای net.Pipe از bytes.Buffer استفاده می‌کنیم تا تست قفل نکند
	var buf bytes.Buffer

	data := []byte("hello reflex")
	// فریم نوع 1 (Data) را در بافر می‌نویسیم
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
