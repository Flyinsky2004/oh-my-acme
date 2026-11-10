package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxAgentResponseBytes = 1 << 20

func agentEndpoint(address string, port int, path string) string {
	return "https://" + net.JoinHostPort(strings.Trim(address, "[]"), strconv.Itoa(port)) + path
}

// Fixed mTLS endpoints carry private keys. Never resend them to a Location
// supplied by an endpoint, even when the destination also has a trusted cert.
func (s *Server) agentHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     &http.Transport{TLSClientConfig: s.cliTLSCfg},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func decodeAgentResponse(resp *http.Response, out any) error {
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read agent response: %w", err)
	}
	if len(body) > maxAgentResponseBytes {
		return fmt.Errorf("agent response exceeds %d bytes", maxAgentResponseBytes)
	}
	return json.Unmarshal(body, out)
}
