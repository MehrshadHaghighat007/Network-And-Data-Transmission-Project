package reflex

// ساختارهای دست‌دهی
type ClientHandshake struct {
	PublicKey [32]byte `json:"pk"`
	UserID    [16]byte `json:"id"`
	Timestamp int64    `json:"ts"`
	Nonce     [16]byte `json:"n"`
	PolicyReq []byte   `json:"p,omitempty"`
}

type ServerHandshake struct {
	PublicKey   [32]byte `json:"pk"`
	PolicyGrant []byte   `json:"pg"`
	Status      string   `json:"status"`
}

// ثابت‌های فریم (فقط یک‌جا تعریف می‌شوند)
const (
	FrameTypeData    byte = 0x01
	FrameTypePadding byte = 0x02
	FrameTypeTiming  byte = 0x03
	FrameTypeClose   byte = 0x0F
)

// ساختار فریم
type Frame struct {
	Type    byte
	Payload []byte
}
