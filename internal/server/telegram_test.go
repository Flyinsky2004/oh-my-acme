package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

func TestTelegramAuthorize(t *testing.T) {
	tests := []struct {
		name       string
		configured int64
		chatID     int64
		senderID   int64
		allowed    bool
		onboarding bool
	}{
		{name: "private chat onboarding", configured: 0, chatID: 123, senderID: 123, onboarding: true},
		{name: "configured private chat", configured: 123, chatID: 123, senderID: 123, allowed: true},
		{name: "different private user", configured: 123, chatID: 456, senderID: 456},
		{name: "group chat rejected", configured: -100123, chatID: -100123, senderID: 456},
		{name: "sender mismatch rejected", configured: 123, chatID: 123, senderID: 456},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, onboarding := telegramAuthorize(tt.configured, tt.chatID, tt.senderID)
			if allowed != tt.allowed || onboarding != tt.onboarding {
				t.Fatalf("telegramAuthorize() = %v, %v, want %v, %v", allowed, onboarding, tt.allowed, tt.onboarding)
			}
		})
	}
}

func TestFormatTelegramOverview(t *testing.T) {
	state := domain.State{
		Certificates: map[string]*domain.Certificate{
			"issued": {RootDomain: "example.com", Current: &domain.CertificateVersion{}},
			"failed": {RootDomain: "failed.example", LastError: "dns timeout"},
		},
		Agents: map[string]*domain.Agent{
			"agent": {Name: "edge"},
		},
		Credentials: map[string]*domain.CloudflareCredential{
			"credential": {Name: "cloudflare"},
		},
	}

	got := formatTelegramOverview(state)
	for _, want := range []string{
		"证书：2",
		"已签发：1",
		"Agent：1",
		"凭据：1",
		"failed.example：dns timeout",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("overview does not contain %q:\n%s", want, got)
		}
	}
}

func TestFormatTelegramCertificate(t *testing.T) {
	cert := &domain.Certificate{
		RootDomain:   "example.com",
		KeyType:      domain.KeyTypeEC256,
		IssueStatus:  domain.StatusSuccess,
		TargetAgents: []string{"a", "b"},
		Current: &domain.CertificateVersion{
			IssuedAt:  time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC),
		},
	}

	got := formatTelegramCertificate(cert)
	for _, want := range []string{"example.com", "已签发", "ec-256", "2026-09-01", "2026-12-01", "目标 Agent：2"} {
		if !strings.Contains(got, want) {
			t.Errorf("certificate text does not contain %q:\n%s", want, got)
		}
	}
}

func TestFormatTelegramAgent(t *testing.T) {
	agent := &domain.Agent{
		Name:          "edge-1",
		Address:       "192.0.2.10",
		Port:          9123,
		Status:        domain.AgentRegistered,
		Version:       "v1.2.3",
		GOOS:          "linux",
		GOARCH:        "amd64",
		LastSeenAt:    time.Date(2026, 9, 4, 10, 30, 0, 0, time.UTC),
		CertExpiresAt: time.Date(2027, 9, 4, 10, 30, 0, 0, time.UTC),
	}

	got := formatTelegramAgent(agent)
	for _, want := range []string{"edge-1", "192.0.2.10:9123", "已注册", "v1.2.3", "linux/amd64", "2026-09-04", "2027-09-04"} {
		if !strings.Contains(got, want) {
			t.Errorf("agent text does not contain %q:\n%s", want, got)
		}
	}
}

func TestTelegramPendingState(t *testing.T) {
	controller := &TelegramController{pending: map[int64]telegramPending{}}
	want := telegramPending{Kind: "certificate-confirm", RootDomain: "example.com", CredentialID: "cred", ACMEID: "ca"}
	controller.setPending(123, want)

	got, ok := controller.pendingFor(123)
	if !ok || got != want {
		t.Fatalf("pendingFor() = %+v, %v, want %+v, true", got, ok, want)
	}
	controller.clearPending(123)
	if _, ok := controller.pendingFor(123); ok {
		t.Fatal("clearPending did not remove the form")
	}
}

func TestTelegramUpdateIdentity(t *testing.T) {
	update := &models.Update{CallbackQuery: &models.CallbackQuery{
		From: models.User{ID: 123},
		Message: models.MaybeInaccessibleMessage{
			Message: &models.Message{Chat: models.Chat{ID: 123}},
		},
	}}
	chatID, senderID, query, ok := telegramUpdateIdentity(update)
	if !ok || chatID != 123 || senderID != 123 || query == nil {
		t.Fatalf("telegramUpdateIdentity() = %d, %d, %v, %v", chatID, senderID, query, ok)
	}
	if _, _, _, ok := telegramUpdateIdentity(nil); ok {
		t.Fatal("telegramUpdateIdentity(nil) reported an identity")
	}
}

func TestTruncateTelegramText(t *testing.T) {
	short := "短消息"
	if got := truncateTelegramText(short); got != short {
		t.Fatalf("short text changed to %q", got)
	}
	long := strings.Repeat("证", telegramTextLimit+10)
	got := truncateTelegramText(long)
	if runes := []rune(got); len(runes) != telegramTextLimit || runes[len(runes)-1] != '…' {
		t.Fatalf("truncated text has %d runes and suffix %q", len(runes), string(runes[len(runes)-1]))
	}
}

func TestTelegramCanMessageRevokedUser(t *testing.T) {
	const token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdef1234"
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithState(true, func(state *domain.State) error {
		state.Config.TelegramEnabled = true
		state.Config.TelegramToken = token
		state.Config.TelegramChatID = 123
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	client, err := bot.New(token, bot.WithSkipGetMe())
	if err != nil {
		t.Fatal(err)
	}
	_, cancel := context.WithCancel(context.Background())
	controller := newTelegramController(&Server{st: st})
	controller.token = token
	controller.cancel = cancel
	controller.activeBot = client
	if !controller.canMessage(client, 123) {
		t.Fatal("authorized user could not receive a message")
	}
	if err := st.WithState(true, func(state *domain.State) error {
		state.Config.TelegramChatID = 0
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if controller.canMessage(client, 123) {
		t.Fatal("clearing the authorized user ID did not revoke ordinary messages")
	}
}

func TestTelegramDraftConsumeAndExpiry(t *testing.T) {
	controller := &TelegramController{pending: map[int64]telegramPending{}}
	controller.setDraft(123, telegramDraft{stage: "target", root: "example.com"})
	if draft, ok := controller.consumeDraft(123, "target"); !ok || draft.root != "example.com" {
		t.Fatalf("consumeDraft() = %+v, %v", draft, ok)
	}
	if _, ok := controller.consumeDraft(123, "target"); ok {
		t.Fatal("draft was consumed more than once")
	}
	controller.setPending(123, telegramPending{Kind: "target", ExpiresAt: time.Now().Add(-time.Second)})
	if _, ok := controller.consumeDraft(123, "target"); ok {
		t.Fatal("expired draft was accepted")
	}
}

func TestTelegramDeploymentSingleFlight(t *testing.T) {
	web, st, _ := newDeployFeedbackTestWeb(t)
	setDeployFeedbackCertificate(t, st, &domain.CertificateVersion{ID: "v1"}, []string{"agent1"})
	if err := st.WithState(true, func(state *domain.State) error {
		state.Certificates["cert1"].DeployStatus = domain.StatusRunning
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	started, err := web.srv.StartDeploy("cert1")
	if err != nil {
		t.Fatal(err)
	}
	if started {
		t.Fatal("duplicate deployment claim succeeded")
	}
}
