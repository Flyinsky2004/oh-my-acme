package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
)

const adminLoginLimit = 50

// Fixed fields and bounds prevent untrusted browser metadata from growing state.
type browserMetadata struct {
	Platform string `json:"platform"`
	Language string `json:"language"`
	Timezone string `json:"timezone"`
	Screen   string `json:"screen"`
	Cores    int    `json:"cores"`
	Touch    int    `json:"touch"`
}

func boundedLoginText(s string, limit int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > limit {
		r = r[:limit]
	}
	return string(r)
}

func (w *Web) recordAdminLogin(r *http.Request, username string, success bool) error {
	ua := boundedLoginText(r.UserAgent(), 1024)
	device, browser := loginDeviceBrowser(ua)
	metadata := browserMetadata{}
	source := "请求头（浏览器信息未提供）"
	raw := r.PostForm.Get("browser_metadata")
	if len(raw) <= 2048 && json.Unmarshal([]byte(raw), &metadata) == nil && metadata != (browserMetadata{}) {
		metadata.Platform = boundedLoginText(metadata.Platform, 128)
		metadata.Language = boundedLoginText(metadata.Language, 128)
		metadata.Timezone = boundedLoginText(metadata.Timezone, 128)
		metadata.Screen = boundedLoginText(metadata.Screen, 64)
		if metadata.Cores < 0 || metadata.Cores > 1024 {
			metadata.Cores = 0
		}
		if metadata.Touch < 0 || metadata.Touch > 100 {
			metadata.Touch = 0
		}
		source = "浏览器环境与请求头"
	} else {
		metadata = browserMetadata{}
	}
	// Canonical JSON keeps key order and input formatting out of the hash.
	payload, _ := json.Marshal(struct {
		UA       string
		Language string
		Metadata browserMetadata
	}{ua, boundedLoginText(r.Header.Get("Accept-Language"), 256), metadata})
	sum := sha256.Sum256(payload)
	record := domain.AdminLogin{
		Username: boundedLoginText(username, 64), Time: time.Now().UTC(),
		IP: loginClientIP(r, w.srv.cfg.TrustedProxies), Success: success,
		Device: device, Browser: browser, UserAgent: ua,
		Fingerprint: hex.EncodeToString(sum[:]), FingerprintSource: source,
	}
	return w.srv.st.WithState(true, func(st *domain.State) error {
		records := make([]domain.AdminLogin, 1, adminLoginLimit)
		records[0] = record
		n := len(st.AdminLogins)
		if n >= adminLoginLimit {
			n = adminLoginLimit - 1
		}
		st.AdminLogins = append(records, st.AdminLogins[:n]...)
		return nil
	})
}

// Only explicitly trusted peers may supply forwarding headers. Walk from the
// nearest proxy toward the client, stopping at the first untrusted address.
func loginClientIP(r *http.Request, proxies []string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return "未知"
	}
	peer = peer.Unmap()
	trusted := func(ip netip.Addr) bool {
		for _, raw := range proxies {
			raw = strings.TrimSpace(raw)
			if addr, err := netip.ParseAddr(raw); err == nil && addr.Unmap() == ip {
				return true
			}
			if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	if !trusted(peer) {
		return peer.String()
	}
	if forwarded := strings.Join(r.Header.Values("X-Forwarded-For"), ","); forwarded != "" {
		chain := strings.Split(forwarded, ",")
		current := peer
		for i := len(chain) - 1; i >= 0; i-- {
			if !trusted(current) {
				return current.String()
			}
			next, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
			if err != nil {
				return peer.String()
			}
			current = next.Unmap()
		}
		return current.String()
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return ip.Unmap().String()
	}
	return peer.String()
}

func loginDeviceBrowser(ua string) (string, string) {
	device := "未知设备"
	switch {
	case strings.Contains(ua, "iPad"):
		device = "iPad / iPadOS"
	case strings.Contains(ua, "iPhone"):
		device = "iPhone / iOS"
	case strings.Contains(ua, "Android"):
		if strings.Contains(ua, "Mobile") {
			device = "手机 / Android"
		} else {
			device = "平板 / Android"
		}
	case strings.Contains(ua, "Windows"):
		device = "电脑 / Windows"
	case strings.Contains(ua, "Macintosh"):
		device = "电脑 / macOS"
	case strings.Contains(ua, "Linux"):
		device = "电脑 / Linux"
	}
	browser := "未知浏览器"
	for _, candidate := range []struct{ token, name string }{
		{"EdgiOS/", "Edge"}, {"EdgA/", "Edge"}, {"Edg/", "Edge"},
		{"OPR/", "Opera"}, {"SamsungBrowser/", "Samsung Internet"},
		{"CriOS/", "Chrome"}, {"Chrome/", "Chrome"},
		{"FxiOS/", "Firefox"}, {"Firefox/", "Firefox"}, {"Version/", "Safari"},
	} {
		if _, rest, ok := strings.Cut(ua, candidate.token); ok {
			version := strings.Fields(rest)
			browser = candidate.name
			if len(version) > 0 {
				browser += " " + strings.TrimRight(version[0], ";)")
			}
			break
		}
	}
	return device, browser
}
