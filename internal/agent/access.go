package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// ExactServerCIDR converts one IP address into an exact host prefix.
func ExactServerCIDR(ipText string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipText))
	if err != nil {
		return "", fmt.Errorf("invalid server IP %q: %w", ipText, err)
	}
	addr = addr.Unmap()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits).String(), nil
}

// ServerCIDRsFromURL resolves the configured registration Server into exact
// host prefixes. It is used only to migrate configurations created before the
// allowlist field existed; new registrations record the connected peer IP.
func ServerCIDRsFromURL(ctx context.Context, serverURL string) ([]string, error) {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return nil, fmt.Errorf("parse server_url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("server_url has no host")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		cidr, err := ExactServerCIDR(addr.String())
		if err != nil {
			return nil, err
		}
		return []string{cidr}, nil
	}

	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve server_url host %q: %w", host, err)
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		cidr, err := ExactServerCIDR(address.String())
		if err != nil || seen[cidr] {
			continue
		}
		seen[cidr] = true
		result = append(result, cidr)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("server_url host %q resolved to no IP addresses", host)
	}
	return result, nil
}

// RestrictListener rejects non-allowlisted peers before the TLS handshake.
func RestrictListener(listener net.Listener, allowedCIDRs []string, log *slog.Logger) (net.Listener, error) {
	prefixes, err := parseServerCIDRs(allowedCIDRs)
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("allowed_server_cidrs must contain at least one IP or CIDR")
	}
	if log == nil {
		log = slog.Default()
	}
	return &allowlistListener{Listener: listener, prefixes: prefixes, log: log}, nil
}

func parseServerCIDRs(entries []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			addr = addr.Unmap()
			bits := 128
			if addr.Is4() {
				bits = 32
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
			continue
		}
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed_server_cidrs entry %q: %w", entry, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

type allowlistListener struct {
	net.Listener
	prefixes []netip.Prefix
	log      *slog.Logger
}

func (l *allowlistListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.allowed(conn.RemoteAddr()) {
			return conn, nil
		}
		// Keep rejection logging at debug level so an Internet scanner cannot
		// amplify connection attempts into persistent log-volume exhaustion.
		l.log.Debug("rejected non-allowlisted agent peer", "remote", conn.RemoteAddr().String())
		_ = conn.Close()
	}
}

func (l *allowlistListener) allowed(remote net.Addr) bool {
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range l.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
