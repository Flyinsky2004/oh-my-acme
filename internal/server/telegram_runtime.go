package server

import (
	"context"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

func (t *TelegramController) runtimeStatus() (string, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status, t.lastError
}

func (t *TelegramController) draft(chatID int64) (telegramDraft, bool) {
	pending, ok := t.pendingFor(chatID)
	if !ok || (!pending.ExpiresAt.IsZero() && time.Now().After(pending.ExpiresAt)) {
		t.clearPending(chatID)
		return telegramDraft{}, false
	}
	return telegramDraft{
		stage:  pending.Kind,
		root:   pending.RootDomain,
		credID: pending.CredentialID,
		caID:   pending.ACMEID,
	}, ok
}

// consumeDraft returns and clears a draft while holding one lock, so a repeated
// callback cannot create a second certificate from the same confirmation.
func (t *TelegramController) consumeDraft(chatID int64, expectedStage string) (telegramDraft, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	pending, ok := t.pending[chatID]
	if !ok || pending.Kind != expectedStage {
		return telegramDraft{}, false
	}
	delete(t.pending, chatID)
	if !pending.ExpiresAt.IsZero() && time.Now().After(pending.ExpiresAt) {
		return telegramDraft{}, false
	}
	return telegramDraft{
		stage:  pending.Kind,
		root:   pending.RootDomain,
		credID: pending.CredentialID,
		caID:   pending.ACMEID,
	}, true
}

func (t *TelegramController) consumePendingAction(chatID int64, kind, targetID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	pending, ok := t.pending[chatID]
	if !ok || pending.Kind != kind || pending.RootDomain != targetID || time.Now().After(pending.ExpiresAt) {
		return false
	}
	delete(t.pending, chatID)
	return true
}

func (t *TelegramController) setDraft(chatID int64, draft telegramDraft) {
	t.setPending(chatID, telegramPending{
		Kind:         draft.stage,
		RootDomain:   draft.root,
		CredentialID: draft.credID,
		ACMEID:       draft.caID,
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	})
}

func (t *TelegramController) clearDraft(chatID int64) {
	t.clearPending(chatID)
}

func (t *TelegramController) setPending(chatID int64, pending telegramPending) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pending == nil {
		t.pending = map[int64]telegramPending{}
	}
	t.pending[chatID] = pending
}

func (t *TelegramController) beginDeployment(certID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.deploying[certID] {
		return false
	}
	t.deploying[certID] = true
	return true
}

func (t *TelegramController) endDeployment(certID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.deploying, certID)
}

func (t *TelegramController) pendingFor(chatID int64) (telegramPending, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	pending, ok := t.pending[chatID]
	return pending, ok
}

func (t *TelegramController) clearPending(chatID int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending, chatID)
}

func (t *TelegramController) answerCallback(ctx context.Context, b *bot.Bot, query *models.CallbackQuery, text string) {
	if query == nil || query.ID == "" {
		return
	}
	requestCtx, cancel := context.WithTimeout(ctx, telegramAPITimeout)
	defer cancel()
	if _, err := b.AnswerCallbackQuery(requestCtx, &bot.AnswerCallbackQueryParams{CallbackQueryID: query.ID, Text: text}); err != nil {
		t.srv.log.Warn("answer Telegram callback failed")
	}
}

func (t *TelegramController) send(ctx context.Context, b *bot.Bot, chatID int64, text string, markup *models.InlineKeyboardMarkup) {
	if b == nil || chatID == 0 || !t.canMessage(b, chatID) {
		return
	}
	t.sendRaw(ctx, b, chatID, text, markup)
}

// sendOnboarding is the only response permitted before a Chat ID is configured.
func (t *TelegramController) sendOnboarding(ctx context.Context, b *bot.Bot, chatID int64, text string) {
	cfg := t.srv.st.State().Config
	if !t.isCurrentBot(b, cfg) {
		return
	}
	_, onboarding := telegramAuthorize(cfg.TelegramChatID, chatID, chatID)
	if onboarding {
		t.sendRaw(ctx, b, chatID, text, nil)
	}
}

func (t *TelegramController) sendRaw(ctx context.Context, b *bot.Bot, chatID int64, text string, markup *models.InlineKeyboardMarkup) {
	requestCtx, cancel := context.WithTimeout(ctx, telegramAPITimeout)
	defer cancel()
	_, err := b.SendMessage(requestCtx, &bot.SendMessageParams{
		ChatID:      chatID,
		Text:        truncateTelegramText(t.redact(text)),
		ReplyMarkup: markup,
	})
	if err != nil && t.srv.Context().Err() == nil {
		t.srv.log.Warn("send Telegram message failed")
	}
}

func (t *TelegramController) redact(text string) string {
	state := t.srv.st.State()
	secrets := make([]string, 0, len(state.Credentials)+1)
	secrets = append(secrets, state.Config.TelegramToken)
	for _, credential := range state.Credentials {
		if credential != nil {
			secrets = append(secrets, credential.Token)
		}
	}
	return redactTelegramText(text, secrets)
}
