package agent

import (
	"context"
	"net"
	"testing"
)

func TestExactServerCIDR(t *testing.T) {
	for _, tt := range []struct {
		ip, want string
	}{
		{ip: "192.0.2.10", want: "192.0.2.10/32"},
		{ip: "2001:db8::10", want: "2001:db8::10/128"},
		{ip: "::ffff:192.0.2.10", want: "192.0.2.10/32"},
	} {
		got, err := ExactServerCIDR(tt.ip)
		if err != nil {
			t.Fatalf("ExactServerCIDR(%q): %v", tt.ip, err)
		}
		if got != tt.want {
			t.Errorf("ExactServerCIDR(%q) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestServerCIDRsFromLiteralURL(t *testing.T) {
	got, err := ServerCIDRsFromURL(context.Background(), "https://192.0.2.10:9444")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "192.0.2.10/32" {
		t.Fatalf("ServerCIDRsFromURL = %v", got)
	}
}

func TestAllowlistListenerAllowsOnlyConfiguredSources(t *testing.T) {
	prefixes, err := parseServerCIDRs([]string{"192.0.2.0/24", "2001:db8::10"})
	if err != nil {
		t.Fatal(err)
	}
	listener := &allowlistListener{prefixes: prefixes}
	for _, tt := range []struct {
		remote string
		want   bool
	}{
		{remote: "192.0.2.25:1234", want: true},
		{remote: "198.51.100.25:1234", want: false},
		{remote: "[2001:db8::10]:1234", want: true},
	} {
		got := listener.allowed(testRemoteAddr(tt.remote))
		if got != tt.want {
			t.Errorf("allowed(%q) = %v, want %v", tt.remote, got, tt.want)
		}
	}
}

func TestRestrictListenerRejectsEmptyOrInvalidAllowlist(t *testing.T) {
	listener := &stubListener{}
	if _, err := RestrictListener(listener, nil, nil); err == nil {
		t.Fatal("expected empty allowlist error")
	}
	if _, err := RestrictListener(listener, []string{"not-an-ip"}, nil); err == nil {
		t.Fatal("expected invalid allowlist error")
	}
}

type testRemoteAddr string

func (a testRemoteAddr) Network() string { return "tcp" }
func (a testRemoteAddr) String() string  { return string(a) }

type stubListener struct{}

func (*stubListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (*stubListener) Close() error              { return nil }
func (*stubListener) Addr() net.Addr            { return testRemoteAddr("127.0.0.1:0") }
