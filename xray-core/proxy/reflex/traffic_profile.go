package reflex

import (
	"math/rand"
	"sync"
	"time"
)

// PacketSizeDist توزیع آماری اندازه بسته‌ها
type PacketSizeDist struct {
	Size   int
	Weight float64
}

// DelayDist توزیع آماری تأخیر بین بسته‌ها
type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

// TrafficProfile ساختار اصلی برای Traffic Morphing
type TrafficProfile struct {
	Name           string
	PacketSizes    []PacketSizeDist
	Delays         []DelayDist
	nextPacketSize int           // برای کنترل داینامیک از طریق PADDING_CTRL
	nextDelay      time.Duration // برای کنترل داینامیک از طریق TIMING_CTRL
	mu             sync.Mutex
}

// Profiles نقشه دسترسی به تمام پروفایل‌های تعریف شده
// در فایل traffic_profile.go

var (
	Profiles = map[string]*TrafficProfile{ // اضافه کردن ستاره قبل از نام تیپ
		"youtube": &YouTubeProfile, // اضافه کردن & قبل از نام متغیر
		"zoom":    &ZoomProfile,    // اضافه کردن & قبل از نام متغیر
	}
)

// YouTubeProfile پروفایل شبیه‌ساز یوتیوب (بسته‌های بزرگ و تأخیر کم)
var YouTubeProfile = TrafficProfile{
	Name: "YouTube",
	PacketSizes: []PacketSizeDist{
		{Size: 1400, Weight: 0.4},
		{Size: 1200, Weight: 0.3},
		{Size: 1000, Weight: 0.2},
		{Size: 800, Weight: 0.1},
	},
	Delays: []DelayDist{
		{Delay: 10 * time.Millisecond, Weight: 0.5},
		{Delay: 20 * time.Millisecond, Weight: 0.3},
		{Delay: 30 * time.Millisecond, Weight: 0.2},
	},
}

// ZoomProfile پروفایل شبیه‌ساز ویدیو کنفرانس (بسته‌های متوسط و تأخیر ثابت)
var ZoomProfile = TrafficProfile{
	Name: "Zoom",
	PacketSizes: []PacketSizeDist{
		{Size: 500, Weight: 0.3},
		{Size: 600, Weight: 0.4},
		{Size: 700, Weight: 0.3},
	},
	Delays: []DelayDist{
		{Delay: 30 * time.Millisecond, Weight: 0.4},
		{Delay: 40 * time.Millisecond, Weight: 0.4},
		{Delay: 50 * time.Millisecond, Weight: 0.2},
	},
}

// GetPacketSize یک اندازه بسته را به صورت تصادفی بر اساس وزن‌ها انتخاب می‌کند
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	// اگر دستور پدینگ خاصی از طرف مقابل رسیده باشد
	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0 // ریست برای استفاده بعدی
		return size
	}

	r := rand.Float64()
	cumsum := 0.0
	for _, dist := range p.PacketSizes {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Size
		}
	}
	return p.PacketSizes[0].Size
}

// GetDelay یک تأخیر زمانی را به صورت تصادفی بر اساس وزن‌ها انتخاب می‌کند
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	// اگر دستور تأخیر خاصی از طرف مقابل رسیده باشد
	if p.nextDelay > 0 {
		delay := p.nextDelay
		p.nextDelay = 0 // ریست برای استفاده بعدی
		return delay
	}

	r := rand.Float64()
	cumsum := 0.0
	for _, dist := range p.Delays {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Delay
		}
	}
	return p.Delays[0].Delay
}

// SetNextPacketSize برای کنترل داینامیک توسط HandleControlFrame
func (p *TrafficProfile) SetNextPacketSize(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextPacketSize = size
}

// SetNextDelay برای کنترل داینامیک توسط HandleControlFrame
func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = delay
}
