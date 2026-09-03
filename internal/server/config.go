package server

// Config is the server's runtime configuration, loaded from config.json
// (written by install.sh) with flags overriding.
type Config struct {
	WebListen     string `json:"web_listen"`
	WebPort       int    `json:"web_port"`
	ControlListen string `json:"control_listen"`
	ControlPort   int    `json:"control_port"`
	DataDir       string `json:"data_dir"`
	PKIDir        string `json:"pki_dir"`
	LogDir        string `json:"log_dir"`
	LogLevel      string `json:"log_level"`

	// External base URL used to build the Web UI / links behind a reverse proxy.
	BaseURL string `json:"base_url,omitempty"`
	// TrustedProxies is a list of IP addresses allowed to set X-Forwarded-*.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
}
