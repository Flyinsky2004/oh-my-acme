package server

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/go-telegram/bot/models"
)

func telegramOnboardingText(chatID int64) string {
	return fmt.Sprintf("当前 Telegram 用户 ID：%d\n请在 Web 设置中保存该值，然后再次发送 /start。", chatID)
}

func telegramOverviewText(state domain.State) string {
	return formatTelegramOverview(state)
}

func formatTelegramOverview(state domain.State) string {
	issued := 0
	failures := make([]string, 0)
	for _, cert := range state.Certificates {
		if cert == nil {
			continue
		}
		if cert.Current != nil {
			issued++
		}
		if cert.LastError != "" {
			failures = append(failures, cert.RootDomain+"："+cert.LastError)
		}
	}
	sort.Strings(failures)
	text := fmt.Sprintf("概览\n证书：%d\n已签发：%d\nAgent：%d\n凭据：%d", len(state.Certificates), issued, len(state.Agents), len(state.Credentials))
	if len(failures) > 0 {
		text += "\n失败：\n" + strings.Join(failures, "\n")
	}
	return text
}

func telegramCertificateText(cert *domain.Certificate) string {
	return formatTelegramCertificate(cert)
}

func formatTelegramCertificate(cert *domain.Certificate) string {
	if cert == nil {
		return "未找到证书。"
	}
	issued, expires := "未签发", "—"
	if cert.Current != nil {
		issued = cert.Current.IssuedAt.Format("2006-01-02 15:04")
		expires = cert.Current.ExpiresAt.Format("2006-01-02 15:04")
	}
	text := fmt.Sprintf("证书：%s\n状态：%s\n密钥类型：%s\n签发时间：%s\n到期时间：%s\n目标 Agent：%d", cert.RootDomain, telegramStatusLabel(cert.IssueStatus), cert.KeyType, issued, expires, len(cert.TargetAgents))
	if cert.LastError != "" {
		text += "\n最近错误：" + cert.LastError
	}
	return text
}

func telegramAgentText(agent *domain.Agent) string {
	return formatTelegramAgent(agent)
}

func formatTelegramAgent(agent *domain.Agent) string {
	if agent == nil {
		return "未找到 Agent。"
	}
	version := agent.Version
	if version == "" {
		version = "—"
	}
	platform := "—"
	if agent.GOOS != "" || agent.GOARCH != "" {
		platform = agent.GOOS + "/" + agent.GOARCH
	}
	lastSeen, expires := "—", "—"
	if !agent.LastSeenAt.IsZero() {
		lastSeen = agent.LastSeenAt.Format("2006-01-02 15:04")
	}
	if !agent.CertExpiresAt.IsZero() {
		expires = agent.CertExpiresAt.Format("2006-01-02 15:04")
	}
	return fmt.Sprintf("Agent：%s\n地址：%s:%d\n状态：%s\n版本：%s\n平台：%s\n最近在线：%s\n身份到期：%s", agent.Name, agent.Address, agent.Port, telegramAgentStatusLabel(agent.Status), version, platform, lastSeen, expires)
}

func telegramCredentialsText(credentials []*domain.CloudflareCredential) string {
	if len(credentials) == 0 {
		return "Cloudflare 凭据\n暂无凭据。"
	}
	lines := make([]string, 0, len(credentials)+1)
	lines = append(lines, "Cloudflare 凭据（只读）")
	for _, credential := range credentials {
		status := "已启用"
		if !credential.Enabled {
			status = "已禁用"
		}
		line := fmt.Sprintf("%s — %s", credential.Name, status)
		if credential.ZoneID != "" {
			line += "，Zone: " + credential.ZoneID
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func telegramStatusLabel(status domain.OperationStatus) string {
	switch status {
	case domain.StatusPending:
		return "待签发"
	case domain.StatusRunning:
		return "签发中"
	case domain.StatusSuccess:
		return "已签发"
	case domain.StatusFailed:
		return "失败"
	default:
		return string(status)
	}
}

func telegramAgentStatusLabel(status domain.AgentStatus) string {
	switch status {
	case domain.AgentRegistered:
		return "已注册"
	case domain.AgentUnreachable:
		return "不可达"
	case domain.AgentDisabled:
		return "已禁用"
	case domain.AgentUnregistered:
		return "未注册"
	default:
		return string(status)
	}
}

func redactTelegramText(text string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[已隐藏]")
		}
	}
	return text
}

func truncateTelegramText(text string) string {
	runes := []rune(text)
	if len(runes) <= telegramTextLimit {
		return text
	}
	return string(runes[:telegramTextLimit-1]) + "…"
}

func truncateTelegramLog(text string) string {
	runes := []rune(text)
	limit := telegramTextLimit - 32
	if len(runes) <= limit {
		return text
	}
	return "…（已省略较早日志）\n" + string(runes[len(runes)-limit:])
}

func telegramMainMenu() *models.InlineKeyboardMarkup {
	return telegramKeyboard([][]models.InlineKeyboardButton{
		telegramRow(telegramButton("概览", "tg:overview"), telegramButton("证书", "tg:certs")),
		telegramRow(telegramButton("Agents", "tg:agents"), telegramButton("凭据", "tg:creds")),
	})
}

func telegramHomeButton() *models.InlineKeyboardMarkup {
	return telegramKeyboard([][]models.InlineKeyboardButton{telegramRow(telegramButton("返回菜单", "tg:home"))})
}

func telegramCancelButton() *models.InlineKeyboardMarkup {
	return telegramKeyboard([][]models.InlineKeyboardButton{telegramRow(telegramButton("取消", "tg:cancel"))})
}

func telegramKeyboard(rows [][]models.InlineKeyboardButton) *models.InlineKeyboardMarkup {
	return &models.InlineKeyboardMarkup{InlineKeyboard: rows}
}

func telegramRow(buttons ...models.InlineKeyboardButton) []models.InlineKeyboardButton {
	return buttons
}

func telegramButton(text, data string) models.InlineKeyboardButton {
	if len(data) > 64 {
		panic("Telegram callback data exceeds 64 bytes")
	}
	return models.InlineKeyboardButton{Text: text, CallbackData: data}
}
