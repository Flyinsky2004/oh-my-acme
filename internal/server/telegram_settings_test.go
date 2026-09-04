package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

func TestParseTelegramChatID(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    int64
		wantErr bool
	}{
		{name: "empty", raw: "", want: 0},
		{name: "whitespace", raw: "  ", want: 0},
		{name: "private chat", raw: "123456789", want: 123456789},
		{name: "group chat rejected", raw: "-1001234567890", wantErr: true},
		{name: "invalid", raw: "chat-id", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTelegramChatID(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseTelegramChatID(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("parseTelegramChatID(%q) = %d, want %d", tt.raw, got, tt.want)
			}
		})
	}
}

func TestHandleSettingsSaveTelegram(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithState(true, func(state *domain.State) error {
		state.Config.TelegramToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdef1234"
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"tg_enabled":  {"on"},
		"tg_token":    {""},
		"tg_chat_id":  {"123456789"},
		"renew_days":  {"30"},
		"dns_sleep":   {"0"},
		"email":       {"admin@example.com"},
		"server_host": {"acme.example.com"},
	}
	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	web := &Web{srv: &Server{st: st}}
	web.handleSettingsSave(rw, req)

	if rw.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rw.Code, http.StatusFound, rw.Body.String())
	}
	cfg := st.State().Config
	if !cfg.TelegramEnabled {
		t.Fatal("TelegramEnabled = false, want true")
	}
	if cfg.TelegramToken != "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdef1234" {
		t.Fatalf("TelegramToken = %q, want existing token preserved", cfg.TelegramToken)
	}
	if cfg.TelegramChatID != 123456789 {
		t.Fatalf("TelegramChatID = %d, want 123456789", cfg.TelegramChatID)
	}
}

func TestHandleSettingsSaveClearsTelegramToken(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithState(true, func(state *domain.State) error {
		state.Config.TelegramToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdef1234"
		state.Config.TelegramEnabled = true
		state.Config.TelegramChatID = 123
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"tg_clear_token": {"on"}, "tg_chat_id": {"0"}}
	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	(&Web{srv: &Server{st: st}}).handleSettingsSave(rw, req)
	if rw.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rw.Code, http.StatusFound, rw.Body.String())
	}
	cfg := st.State().Config
	if cfg.TelegramEnabled || cfg.TelegramToken != "" || cfg.TelegramChatID != 0 {
		t.Fatalf("Telegram config was not cleared: %+v", cfg)
	}
}

func TestHandleSettingsSaveRejectsInvalidTelegramConfig(t *testing.T) {
	tests := []struct {
		name string
		form url.Values
	}{
		{
			name: "invalid chat id",
			form: url.Values{"tg_enabled": {"on"}, "tg_token": {"123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdef1234"}, "tg_chat_id": {"invalid"}},
		},
		{
			name: "enabled without token",
			form: url.Values{"tg_enabled": {"on"}, "tg_chat_id": {"123"}},
		},
		{
			name: "malformed token",
			form: url.Values{"tg_enabled": {"on"}, "tg_token": {"not-a-token"}, "tg_chat_id": {"123"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, err := store.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()

			web := &Web{srv: &Server{st: st}}
			web.handleSettingsSave(rw, req)

			if rw.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body=%s", rw.Code, http.StatusBadRequest, rw.Body.String())
			}
			cfg := st.State().Config
			if cfg.TelegramEnabled || cfg.TelegramToken != "" || cfg.TelegramChatID != 0 {
				t.Fatalf("invalid request mutated config: %+v", cfg)
			}
		})
	}
}
