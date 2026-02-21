package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func main() {
	// ۱. ایجاد یک سایت فیک داخلی (مقصد Fallback)
	fakeSite := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<h1>Welcome to My Personal Blog</h1><p>Reflex Protocol is Hidden!</p>")
	}))
	defer fakeSite.Close()

	// استخراج پورت سایت فیک
	_, portStr, _ := net.SplitHostPort(fakeSite.Listener.Addr().String())
	var port uint32
_, _ = fmt.Sscanf(portStr, "%d", &port)

	// ۲. تنظیم هندلر ریفلکس با Fallback به سایت فیک
	handler := &inbound.Handler{}
	// توجه: در دنیای واقعی این تنظیمات از Config خوانده می‌شود
	// ما اینجا مستقیم شبیه‌سازی می‌کنیم

	// ۳. گوش دادن روی پورت ۸۰۸۰ برای تست شما
	listener, _ := net.Listen("tcp", "127.0.0.1:8080")
	fmt.Println("🚀 Reflex Server started on http://127.0.0.1:8080")
	fmt.Printf("🎯 Fallback destination: http://127.0.0.1:%d\n", port)

	for {
		conn, _ := listener.Accept()
		go func(c net.Conn) {
			// تبدیل کانکشن به تایپ مورد نیاز Xray
			statConn := c.(stat.Connection)
_ = handler.Process(context.Background(), corenet.Network_TCP, statConn, nil)
		}(conn)
	}
}
