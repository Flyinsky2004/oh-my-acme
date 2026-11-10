package server

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// Origin protection is deliberately exact: a request may only mutate state when
// its Origin (or, when Origin is absent, its Referer) names the same scheme and
// authority the server itself believes it is serving. Forwarded headers are
// honoured only when the immediate peer is a configured trusted proxy, so an
// arbitrary client cannot spoof its way to a same-origin verdict.

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// trustedPeer reports whether the direct connection comes from a configured
// reverse proxy.
func (w *Web) trustedPeer(r *http.Request) bool {
	if w == nil || w.srv == nil {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return trustedProxyIP(ip.Unmap(), w.srv.cfg.TrustedProxies)
}

// requestScheme is the scheme the browser used. X-Forwarded-Proto and the
// standard Forwarded header are accepted only from a trusted proxy.
func (w *Web) requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if w.trustedPeer(r) {
		if proto := strings.ToLower(firstForwardedValue(r.Header.Get("X-Forwarded-Proto"))); proto == "https" {
			return "https"
		}
		if proto := strings.ToLower(forwardedParam(r.Header.Get("Forwarded"), "proto")); proto == "https" {
			return "https"
		}
	}
	return "http"
}

// requestHost is the authority the browser addressed. X-Forwarded-Host and the
// standard Forwarded host parameter are accepted only from a trusted proxy.
func (w *Web) requestHost(r *http.Request) string {
	if w.trustedPeer(r) {
		if host := firstForwardedValue(r.Header.Get("X-Forwarded-Host")); host != "" {
			return host
		}
		if host := forwardedParam(r.Header.Get("Forwarded"), "host"); host != "" {
			return host
		}
	}
	return r.Host
}

// originAllowed accepts requests with no Origin/Referer (headless CLI clients
// and tests) and rejects any that clearly name a different origin. Browsers
// always attach Origin to cross-site state-changing requests, so a mismatch is
// either an attack or a broken deployment.
func (w *Web) originAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if origin == "" && referer == "" {
		return true
	}
	scheme := w.requestScheme(r)
	host := w.requestHost(r)
	if origin != "" {
		// An Origin is a bare scheme://authority; a path, query, fragment or
		// userinfo means the header is malformed or forged.
		return originMatches(origin, scheme, host, false)
	}
	// A Referer is a full URL; its path is expected and ignored.
	return originMatches(referer, scheme, host, true)
}

func originMatches(raw, scheme, host string, allowPath bool) bool {
	if raw == "" || strings.EqualFold(raw, "null") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.User != nil {
		return false
	}
	if !allowPath && (u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "") {
		return false
	}
	if !strings.EqualFold(u.Scheme, scheme) {
		return false
	}
	want := canonicalAuthority(host, scheme)
	got := canonicalAuthority(u.Host, scheme)
	return want != "" && got != "" && want == got
}

// canonicalAuthority lower-cases the host and drops the scheme's default port
// so "example.com", "example.com:443" and "EXAMPLE.com:443" compare equal for
// https while a genuinely different authority never does.
func canonicalAuthority(authority, scheme string) string {
	authority = strings.ToLower(strings.TrimSpace(authority))
	if authority == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return strings.Trim(authority, "[]")
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return host
	}
	return net.JoinHostPort(host, port)
}

func firstForwardedValue(value string) string {
	if i := strings.IndexByte(value, ','); i >= 0 {
		value = value[:i]
	}
	return strings.TrimSpace(value)
}

// forwardedParam extracts a parameter from the first element of an RFC 7239
// Forwarded header, e.g. Forwarded: proto=https;host=acme.example.com.
func forwardedParam(header, key string) string {
	if header == "" {
		return ""
	}
	first := strings.Split(header, ",")[0]
	for _, part := range strings.Split(first, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(name), key) {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return ""
}
