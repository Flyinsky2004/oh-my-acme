package server

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

const (
	telegramAPITimeout = 10 * time.Second
	telegramDeployWait = 5 * time.Minute
	telegramIssueWait  = 27 * time.Minute
	telegramTextLimit  = 3800
)

// TelegramController owns the optional long-polling Telegram bot and its
// short-lived, per-chat certificate creation drafts.
type TelegramController struct {
	srv *Server

	reconcileMu sync.Mutex
	mu          sync.Mutex
	token       string
	cancel      context.CancelFunc
	done        chan struct{}
	activeBot   *bot.Bot
	status      string
	lastError   string
	pending     map[int64]telegramPending
	deploying   map[string]bool
}

type telegramDraft struct {
	stage  string
	root   string
	credID string
	caID   string
}

// telegramPending is the per-chat state for multi-step interactions.
type telegramPending struct {
	Kind         string
	RootDomain   string
	CredentialID string
	ACMEID       string
	ExpiresAt    time.Time
}

func newTelegramController(srv *Server) *TelegramController {
	return &TelegramController{
		srv:       srv,
		status:    "disabled",
		pending:   map[int64]telegramPending{},
		deploying: map[string]bool{},
	}
}

// Reconcile applies the persisted bot settings asynchronously so Telegram's
// getMe validation never delays Server startup or an HTTP settings save.
func (t *TelegramController) Reconcile() {
	cfg := t.srv.st.State().Config
	token := strings.TrimSpace(cfg.TelegramToken)
	t.mu.Lock()
	switch {
	case !cfg.TelegramEnabled || token == "":
		t.status, t.lastError = "disabled", ""
	case token == t.token && t.cancel != nil:
		t.status, t.lastError = "running", ""
	default:
		t.status, t.lastError = "starting", ""
	}
	t.mu.Unlock()
	t.srv.Go(func(context.Context) { t.reconcile() })
}

// reconcile serializes replacements so a new poller starts only after its
// predecessor and all synchronous handlers have stopped.
func (t *TelegramController) reconcile() {
	t.reconcileMu.Lock()
	defer t.reconcileMu.Unlock()

	cfg := t.srv.st.State().Config
	token := strings.TrimSpace(cfg.TelegramToken)
	if !cfg.TelegramEnabled || token == "" {
		token = ""
	}

	t.mu.Lock()
	if token != "" && token == t.token && t.cancel != nil {
		t.mu.Unlock()
		return
	}
	previousCancel, previousDone := t.cancel, t.done
	t.mu.Unlock()

	if token == "" {
		t.stopPoller(previousCancel, previousDone)
		return
	}

	// Validate a replacement before stopping the currently working bot. Raw
	// dependency errors are intentionally omitted because request URLs contain
	// the Telegram token.
	b, err := bot.New(token,
		bot.WithCheckInitTimeout(telegramAPITimeout),
		bot.WithAllowedUpdates(bot.AllowedUpdates{models.AllowedUpdateMessage, models.AllowedUpdateCallbackQuery}),
		bot.WithDefaultHandler(t.handleUpdate),
		bot.WithErrorsHandler(t.handleBotError),
		bot.WithWorkers(1),
		bot.WithNotAsyncHandlers(),
	)
	if err != nil {
		t.mu.Lock()
		t.status, t.lastError = "failed", "Bot Token 无效或 Telegram API 不可达"
		t.mu.Unlock()
		t.srv.log.Warn("initialize Telegram bot failed")
		return
	}
	latest := t.srv.st.State().Config
	if !latest.TelegramEnabled || strings.TrimSpace(latest.TelegramToken) != token {
		return
	}

	t.stopPoller(previousCancel, previousDone)
	if t.srv.Context().Err() != nil {
		return
	}
	pollCtx, cancel := context.WithCancel(t.srv.Context())
	done := make(chan struct{})
	t.mu.Lock()
	t.token, t.cancel, t.done, t.activeBot = token, cancel, done, b
	t.status, t.lastError = "running", ""
	t.mu.Unlock()
	t.srv.Go(func(context.Context) {
		defer close(done)
		defer t.clearPoller(token, done)
		b.Start(pollCtx)
	})
	t.srv.log.Info("Telegram bot polling started")
}

func (t *TelegramController) stopPoller(cancel context.CancelFunc, done chan struct{}) {
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-t.srv.Context().Done():
			return
		}
	}
	t.mu.Lock()
	if t.done == done {
		t.token, t.cancel, t.done, t.activeBot = "", nil, nil, nil
		t.pending = map[int64]telegramPending{}
	}
	t.mu.Unlock()
}

func (t *TelegramController) clearPoller(token string, done chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token == token && t.done == done {
		t.token, t.cancel, t.done, t.activeBot = "", nil, nil, nil
		t.pending = map[int64]telegramPending{}
	}
}

func (t *TelegramController) isCurrentBot(b *bot.Bot, cfg domain.SystemConfig) bool {
	if b == nil || !cfg.TelegramEnabled || strings.TrimSpace(cfg.TelegramToken) == "" || b.Token() != strings.TrimSpace(cfg.TelegramToken) {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.activeBot == b && t.cancel != nil
}

// canMessage prevents a replaced or disabled bot from sending a late result.
func (t *TelegramController) canMessage(b *bot.Bot, chatID int64) bool {
	cfg := t.srv.st.State().Config
	if !t.isCurrentBot(b, cfg) {
		return false
	}
	allowed, _ := telegramAuthorize(cfg.TelegramChatID, chatID, chatID)
	return allowed
}

func (t *TelegramController) handleBotError(err error) {
	if err != nil && t.srv.Context().Err() == nil {
		// The dependency may include a request URL in its error. Do not log it:
		// Telegram bot tokens are part of that URL.
		t.srv.log.Warn("Telegram bot request failed")
	}
}

func (t *TelegramController) handleUpdate(ctx context.Context, b *bot.Bot, update *models.Update) {
	chatID, senderID, callback, ok := telegramUpdateIdentity(update)
	if !ok {
		return
	}

	cfg := t.srv.st.State().Config
	if !t.isCurrentBot(b, cfg) {
		return
	}
	allowed, onboarding := telegramAuthorize(cfg.TelegramChatID, chatID, senderID)
	if onboarding {
		// Before the user is configured, expose only the private-chat ID.
		t.sendOnboarding(ctx, b, chatID, telegramOnboardingText(chatID))
		return
	}
	if !allowed {
		return
	}

	if callback != nil {
		t.answerCallback(ctx, b, callback, "")
		if ctx.Err() != nil || !t.canMessage(b, chatID) {
			return
		}
		t.handleCallback(ctx, b, chatID, callback.Data)
		return
	}
	if update == nil || update.Message == nil || ctx.Err() != nil || !t.canMessage(b, chatID) {
		return
	}
	t.handleMessage(ctx, b, chatID, update.Message.Text)
}

func telegramUpdateIdentity(update *models.Update) (int64, int64, *models.CallbackQuery, bool) {
	if update == nil {
		return 0, 0, nil, false
	}
	if update.Message != nil {
		if update.Message.From == nil {
			return 0, 0, nil, false
		}
		return update.Message.Chat.ID, update.Message.From.ID, nil, true
	}
	query := update.CallbackQuery
	if query == nil {
		return 0, 0, nil, false
	}
	if query.Message.Message != nil {
		return query.Message.Message.Chat.ID, query.From.ID, query, true
	}
	if query.Message.InaccessibleMessage != nil {
		return query.Message.InaccessibleMessage.Chat.ID, query.From.ID, query, true
	}
	return 0, 0, nil, false
}

// telegramAuthorize permits only a private conversation: Telegram uses the same
// positive ID for a user and that user's private chat. This prevents every
// member of a configured group from inheriting administrator access.
func telegramAuthorize(configuredID, chatID, senderID int64) (allowed, onboarding bool) {
	if chatID <= 0 || senderID <= 0 || senderID != chatID {
		return false, false
	}
	if configuredID == 0 {
		return false, true
	}
	return configuredID == chatID, false
}

func (t *TelegramController) handleMessage(ctx context.Context, b *bot.Bot, chatID int64, text string) {
	command := strings.Fields(text)
	if len(command) > 0 && telegramCommand(command[0]) == "/start" {
		t.clearDraft(chatID)
		t.send(ctx, b, chatID, "oh-my-acme 管理菜单", telegramMainMenu())
		return
	}

	draft, ok := t.draft(chatID)
	if !ok {
		t.send(ctx, b, chatID, "请使用 /start 打开管理菜单。", nil)
		return
	}
	switch draft.stage {
	case "root":
		t.handleDraftRoot(ctx, b, chatID, text)
	case "agent-name":
		t.handleAgentName(ctx, b, chatID, text)
	default:
		t.send(ctx, b, chatID, "请使用下方按钮继续，或使用 /start 重新开始。", nil)
	}
}

func telegramCommand(command string) string {
	command = strings.ToLower(command)
	if i := strings.IndexByte(command, '@'); i >= 0 {
		return command[:i]
	}
	return command
}

func (t *TelegramController) handleCallback(ctx context.Context, b *bot.Bot, chatID int64, data string) {
	switch data {
	case "tg:home":
		t.clearDraft(chatID)
		t.send(ctx, b, chatID, "oh-my-acme 管理菜单", telegramMainMenu())
	case "tg:overview":
		t.send(ctx, b, chatID, telegramOverviewText(t.srv.st.State()), telegramHomeButton())
	case "tg:certs":
		t.showCertificates(ctx, b, chatID)
	case "tg:cert-new":
		t.setDraft(chatID, telegramDraft{stage: "root"})
		t.send(ctx, b, chatID, "请输入根域名，例如 example.com。将同时签发 example.com 和 *.example.com。", telegramCancelButton())
	case "tg:agents":
		t.showAgents(ctx, b, chatID)
	case "tg:agent-new":
		t.setDraft(chatID, telegramDraft{stage: "agent-name"})
		t.send(ctx, b, chatID, "请输入新 Agent 的名称。", telegramCancelButton())
	case "tg:creds":
		t.showCredentials(ctx, b, chatID)
	case "tg:cancel":
		t.clearDraft(chatID)
		t.send(ctx, b, chatID, "已取消。", telegramMainMenu())
	case "tg:new-target-all":
		t.finishCertificateDraft(ctx, b, chatID, true)
	case "tg:new-target-none":
		t.finishCertificateDraft(ctx, b, chatID, false)
	default:
		t.handleEntityCallback(ctx, b, chatID, data)
	}
}

func (t *TelegramController) handleEntityCallback(ctx context.Context, b *bot.Bot, chatID int64, data string) {
	switch {
	case strings.HasPrefix(data, "tg:cert:"):
		t.showCertificate(ctx, b, chatID, strings.TrimPrefix(data, "tg:cert:"))
	case strings.HasPrefix(data, "tg:issue:"):
		t.startIssue(ctx, b, chatID, strings.TrimPrefix(data, "tg:issue:"))
	case strings.HasPrefix(data, "tg:deploy:"):
		t.startDeploy(ctx, b, chatID, strings.TrimPrefix(data, "tg:deploy:"))
	case strings.HasPrefix(data, "tg:log:"):
		t.showCertificateLog(ctx, b, chatID, strings.TrimPrefix(data, "tg:log:"))
	case strings.HasPrefix(data, "tg:del-cert-ok:"):
		t.deleteCertificate(ctx, b, chatID, strings.TrimPrefix(data, "tg:del-cert-ok:"))
	case strings.HasPrefix(data, "tg:del-cert:"):
		t.confirmCertificateDelete(ctx, b, chatID, strings.TrimPrefix(data, "tg:del-cert:"))
	case strings.HasPrefix(data, "tg:new-cred:"):
		t.selectCredential(ctx, b, chatID, strings.TrimPrefix(data, "tg:new-cred:"))
	case strings.HasPrefix(data, "tg:new-ca:"):
		t.selectCA(ctx, b, chatID, strings.TrimPrefix(data, "tg:new-ca:"))
	case strings.HasPrefix(data, "tg:agent:"):
		t.showAgent(ctx, b, chatID, strings.TrimPrefix(data, "tg:agent:"))
	case strings.HasPrefix(data, "tg:del-agent-ok:"):
		t.deleteAgent(ctx, b, chatID, strings.TrimPrefix(data, "tg:del-agent-ok:"))
	case strings.HasPrefix(data, "tg:del-agent:"):
		t.confirmAgentDelete(ctx, b, chatID, strings.TrimPrefix(data, "tg:del-agent:"))
	default:
		t.send(ctx, b, chatID, "操作已失效，请使用 /start 返回菜单。", nil)
	}
}

func (t *TelegramController) showCertificates(ctx context.Context, b *bot.Bot, chatID int64) {
	state := t.srv.st.State()
	certs := make([]*domain.Certificate, 0, len(state.Certificates))
	for _, cert := range state.Certificates {
		if cert != nil {
			certs = append(certs, cert)
		}
	}
	sort.Slice(certs, func(i, j int) bool { return certs[i].RootDomain < certs[j].RootDomain })
	rows := make([][]models.InlineKeyboardButton, 0, len(certs)+2)
	for _, cert := range certs {
		rows = append(rows, telegramRow(telegramButton(cert.RootDomain, "tg:cert:"+cert.ID)))
	}
	rows = append(rows, telegramRow(telegramButton("新建证书", "tg:cert-new")), telegramRow(telegramButton("返回菜单", "tg:home")))
	t.send(ctx, b, chatID, fmt.Sprintf("证书列表（%d）", len(certs)), telegramKeyboard(rows))
}

func (t *TelegramController) showCertificate(ctx context.Context, b *bot.Bot, chatID int64, certID string) {
	t.clearPending(chatID)
	cert := t.srv.st.State().Certificates[certID]
	if cert == nil {
		t.send(ctx, b, chatID, "未找到该证书。", telegramHomeButton())
		return
	}
	rows := [][]models.InlineKeyboardButton{
		telegramRow(telegramButton("异步签发", "tg:issue:"+cert.ID), telegramButton("异步部署", "tg:deploy:"+cert.ID)),
		telegramRow(telegramButton("查看日志", "tg:log:"+cert.ID)),
		telegramRow(telegramButton("删除证书", "tg:del-cert:"+cert.ID)),
		telegramRow(telegramButton("返回证书列表", "tg:certs")),
	}
	t.send(ctx, b, chatID, telegramCertificateText(cert), telegramKeyboard(rows))
}

func (t *TelegramController) startIssue(ctx context.Context, b *bot.Bot, chatID int64, certID string) {
	cert := t.srv.st.State().Certificates[certID]
	if cert == nil {
		t.send(ctx, b, chatID, "未找到该证书。", nil)
		return
	}
	_, started, err := t.srv.StartIssue(certID, taskTypeIssue)
	if err != nil {
		t.send(ctx, b, chatID, "无法开始签发："+err.Error(), nil)
		return
	}
	if started {
		t.srv.log.Info("telegram privileged action", "action", "issue_certificate", "chat_id", chatID, "certificate_id", certID)
		t.send(ctx, b, chatID, "已开始异步签发 "+cert.RootDomain+"。手动签发完成后不会自动部署；请选择“异步部署”进行下发。", nil)
		return
	}
	t.send(ctx, b, chatID, "该证书已有签发任务在运行。", nil)
}

func (t *TelegramController) startDeploy(ctx context.Context, b *bot.Bot, chatID int64, certID string) {
	cert := t.srv.st.State().Certificates[certID]
	if cert == nil || cert.Current == nil {
		t.send(ctx, b, chatID, "证书尚未签发成功，无法部署。", nil)
		return
	}
	if !t.beginDeployment(certID) {
		t.send(ctx, b, chatID, "该证书已有部署任务正在运行。", nil)
		return
	}
	t.send(ctx, b, chatID, "已开始异步部署到目标 Agents。", nil)
	t.srv.log.Info("telegram privileged action", "action", "deploy_certificate", "chat_id", chatID, "certificate_id", certID)
	t.srv.Go(func(parent context.Context) {
		defer t.endDeployment(certID)
		deployCtx, cancel := context.WithTimeout(parent, telegramDeployWait)
		defer cancel()
		err := t.srv.DeployAll(deployCtx, certID)
		if parent.Err() != nil {
			return
		}
		if err != nil {
			t.send(t.srv.Context(), b, chatID, "部署失败："+err.Error(), nil)
			return
		}
		t.send(t.srv.Context(), b, chatID, "证书部署完成。", nil)
	})
}

func (t *TelegramController) showCertificateLog(ctx context.Context, b *bot.Bot, chatID int64, certID string) {
	if t.srv.st.State().Certificates[certID] == nil {
		t.send(ctx, b, chatID, "未找到该证书。", nil)
		return
	}
	logText, err := t.srv.st.ReadCertificateLog(certID)
	if err != nil {
		t.send(ctx, b, chatID, "读取签发日志失败："+err.Error(), nil)
		return
	}
	if strings.TrimSpace(logText) == "" {
		logText = "暂无签发日志。"
	}
	t.send(ctx, b, chatID, "签发日志\n"+truncateTelegramLog(logText), telegramKeyboard([][]models.InlineKeyboardButton{telegramRow(telegramButton("返回证书", "tg:cert:"+certID))}))
}

func (t *TelegramController) confirmCertificateDelete(ctx context.Context, b *bot.Bot, chatID int64, certID string) {
	cert := t.srv.st.State().Certificates[certID]
	if cert == nil {
		t.send(ctx, b, chatID, "未找到该证书。", nil)
		return
	}
	t.setPending(chatID, telegramPending{Kind: "delete-certificate", RootDomain: cert.ID, ExpiresAt: time.Now().Add(2 * time.Minute)})
	markup := telegramKeyboard([][]models.InlineKeyboardButton{
		telegramRow(telegramButton("确认删除", "tg:del-cert-ok:"+cert.ID), telegramButton("取消", "tg:cert:"+cert.ID)),
	})
	t.send(ctx, b, chatID, "确认删除证书 "+cert.RootDomain+"？此操作会移除证书文件和任务记录。", markup)
}

func (t *TelegramController) deleteCertificate(ctx context.Context, b *bot.Bot, chatID int64, certID string) {
	if !t.consumePendingAction(chatID, "delete-certificate", certID) {
		t.send(ctx, b, chatID, "删除确认已失效，请重新操作。", telegramHomeButton())
		return
	}
	if err := t.srv.DeleteCertificate(certID); err != nil {
		t.send(ctx, b, chatID, "删除证书失败："+err.Error(), nil)
		return
	}
	t.srv.log.Info("telegram privileged action", "action", "delete_certificate", "chat_id", chatID, "certificate_id", certID)
	t.send(ctx, b, chatID, "证书已删除。", telegramHomeButton())
}

func (t *TelegramController) handleDraftRoot(ctx context.Context, b *bot.Bot, chatID int64, text string) {
	root := normalizeDomain(text)
	if !validDomain(root) {
		t.send(ctx, b, chatID, "根域名无效，请输入类似 example.com 的域名。", telegramCancelButton())
		return
	}
	t.setDraft(chatID, telegramDraft{stage: "credential", root: root})
	state := t.srv.st.State()
	credentials := make([]*domain.CloudflareCredential, 0, len(state.Credentials))
	for _, credential := range state.Credentials {
		if credential != nil && credential.Enabled {
			credentials = append(credentials, credential)
		}
	}
	sort.Slice(credentials, func(i, j int) bool { return credentials[i].Name < credentials[j].Name })
	if len(credentials) == 0 {
		t.clearDraft(chatID)
		t.send(ctx, b, chatID, "没有可用的 Cloudflare 凭据。请先在 Web 管理界面创建凭据。", telegramHomeButton())
		return
	}
	rows := make([][]models.InlineKeyboardButton, 0, len(credentials)+1)
	for _, credential := range credentials {
		rows = append(rows, telegramRow(telegramButton(credential.Name, "tg:new-cred:"+credential.ID)))
	}
	rows = append(rows, telegramRow(telegramButton("取消", "tg:cancel")))
	t.send(ctx, b, chatID, "选择用于 DNS-01 验证的 Cloudflare 凭据：", telegramKeyboard(rows))
}

func (t *TelegramController) selectCredential(ctx context.Context, b *bot.Bot, chatID int64, credentialID string) {
	draft, ok := t.draft(chatID)
	credential := t.srv.st.State().Credentials[credentialID]
	if !ok || draft.stage != "credential" || credential == nil || !credential.Enabled {
		t.send(ctx, b, chatID, "凭据选择已失效，请重新新建证书。", telegramHomeButton())
		return
	}
	draft.stage, draft.credID = "ca", credentialID
	t.setDraft(chatID, draft)

	state := t.srv.st.State()
	cas := make([]*domain.ACMECA, 0, len(state.CAs))
	for _, ca := range state.CAs {
		if ca != nil && ca.Enabled {
			cas = append(cas, ca)
		}
	}
	sort.Slice(cas, func(i, j int) bool { return cas[i].Name < cas[j].Name })
	if len(cas) == 0 {
		t.clearDraft(chatID)
		t.send(ctx, b, chatID, "没有可用的 ACME CA。", telegramHomeButton())
		return
	}
	rows := make([][]models.InlineKeyboardButton, 0, len(cas)+1)
	for _, ca := range cas {
		label := ca.Name
		if ca.ID == state.Config.DefaultACMEID {
			label += "（默认）"
		}
		rows = append(rows, telegramRow(telegramButton(label, "tg:new-ca:"+ca.ID)))
	}
	rows = append(rows, telegramRow(telegramButton("取消", "tg:cancel")))
	t.send(ctx, b, chatID, "选择 ACME CA：", telegramKeyboard(rows))
}

func (t *TelegramController) selectCA(ctx context.Context, b *bot.Bot, chatID int64, caID string) {
	draft, ok := t.draft(chatID)
	ca := t.srv.st.State().CAs[caID]
	if !ok || draft.stage != "ca" || ca == nil || !ca.Enabled {
		t.send(ctx, b, chatID, "CA 选择已失效，请重新新建证书。", telegramHomeButton())
		return
	}
	draft.stage, draft.caID = "target", caID
	t.setDraft(chatID, draft)
	message := "确认创建并异步签发 " + draft.root + "？\n"
	message += "签发会在后台执行。若选择所有已注册 Agents，签发成功后机器人会等待完成并调用部署；手动签发本身不会自动部署。"
	markup := telegramKeyboard([][]models.InlineKeyboardButton{
		telegramRow(telegramButton("所有已注册 Agents 并签发", "tg:new-target-all")),
		telegramRow(telegramButton("不指定 Agent，直接签发", "tg:new-target-none")),
		telegramRow(telegramButton("取消", "tg:cancel")),
	})
	t.send(ctx, b, chatID, message, markup)
}

func (t *TelegramController) finishCertificateDraft(ctx context.Context, b *bot.Bot, chatID int64, targetAll bool) {
	draft, ok := t.consumeDraft(chatID, "target")
	if !ok {
		t.send(ctx, b, chatID, "证书创建流程已失效，请重新开始。", telegramHomeButton())
		return
	}

	var targetAgents []string
	if targetAll {
		targetAgents = telegramRegisteredAgentIDs(t.srv.st.State())
	}
	certID, err := t.srv.CreateCertificate(draft.root, draft.credID, draft.caID, "", targetAgents)
	if err != nil {
		t.send(ctx, b, chatID, "创建证书失败："+err.Error(), telegramHomeButton())
		return
	}
	t.srv.log.Info("telegram privileged action", "action", "create_certificate", "chat_id", chatID, "certificate_id", certID)
	_, started, err := t.srv.StartIssue(certID, taskTypeIssue)
	if err != nil {
		t.send(ctx, b, chatID, "证书已创建，但无法开始签发："+err.Error(), telegramHomeButton())
		return
	}
	if !started {
		t.send(ctx, b, chatID, "证书已创建，签发任务已在运行。", telegramHomeButton())
		return
	}
	t.send(ctx, b, chatID, "证书已创建，签发正在后台执行。", telegramHomeButton())
	if targetAll {
		t.srv.Go(func(parent context.Context) {
			t.waitForIssueAndDeploy(parent, b, chatID, certID)
		})
	}
}

func telegramRegisteredAgentIDs(state domain.State) []string {
	ids := make([]string, 0, len(state.Agents))
	for id, agent := range state.Agents {
		if agent != nil && agent.Status == domain.AgentRegistered {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (t *TelegramController) waitForIssueAndDeploy(parent context.Context, b *bot.Bot, chatID int64, certID string) {
	deadline := time.NewTimer(telegramIssueWait)
	defer deadline.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		cert := t.srv.st.State().Certificates[certID]
		if cert == nil {
			return
		}
		switch cert.IssueStatus {
		case domain.StatusSuccess:
			if !t.beginDeployment(certID) {
				t.send(t.srv.Context(), b, chatID, "签发已完成；已有部署任务正在运行。", nil)
				return
			}
			defer t.endDeployment(certID)
			deployCtx, cancel := context.WithTimeout(parent, telegramDeployWait)
			err := t.srv.DeployAll(deployCtx, certID)
			cancel()
			if err != nil {
				t.send(t.srv.Context(), b, chatID, "签发已完成，但部署失败："+err.Error(), nil)
				return
			}
			t.send(t.srv.Context(), b, chatID, "签发和部署均已完成。", nil)
			return
		case domain.StatusFailed:
			t.send(t.srv.Context(), b, chatID, "签发失败："+cert.LastError, nil)
			return
		}
		select {
		case <-parent.Done():
			return
		case <-deadline.C:
			t.send(t.srv.Context(), b, chatID, "等待签发完成超时；请在证书详情中查看状态。", nil)
			return
		case <-ticker.C:
		}
	}
}

func (t *TelegramController) showAgents(ctx context.Context, b *bot.Bot, chatID int64) {
	state := t.srv.st.State()
	agents := make([]*domain.Agent, 0, len(state.Agents))
	for _, agent := range state.Agents {
		if agent != nil {
			agents = append(agents, agent)
		}
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })
	rows := make([][]models.InlineKeyboardButton, 0, len(agents)+2)
	for _, agent := range agents {
		rows = append(rows, telegramRow(telegramButton(agent.Name, "tg:agent:"+agent.ID)))
	}
	rows = append(rows, telegramRow(telegramButton("生成新 Agent 安装命令", "tg:agent-new")), telegramRow(telegramButton("返回菜单", "tg:home")))
	t.send(ctx, b, chatID, fmt.Sprintf("Agent 列表（%d）", len(agents)), telegramKeyboard(rows))
}

func (t *TelegramController) showAgent(ctx context.Context, b *bot.Bot, chatID int64, agentID string) {
	t.clearPending(chatID)
	agent := t.srv.st.State().Agents[agentID]
	if agent == nil {
		t.send(ctx, b, chatID, "未找到该 Agent。", telegramHomeButton())
		return
	}
	markup := telegramKeyboard([][]models.InlineKeyboardButton{
		telegramRow(telegramButton("删除 Agent", "tg:del-agent:"+agent.ID)),
		telegramRow(telegramButton("返回 Agent 列表", "tg:agents")),
	})
	t.send(ctx, b, chatID, telegramAgentText(agent), markup)
}

func (t *TelegramController) handleAgentName(ctx context.Context, b *bot.Bot, chatID int64, text string) {
	name := strings.TrimSpace(text)
	if name == "" {
		t.send(ctx, b, chatID, "Agent 名称不能为空。", telegramCancelButton())
		return
	}
	t.clearDraft(chatID)
	t.createAgentTokenForName(ctx, b, chatID, name)
}

func (t *TelegramController) createAgentTokenForName(ctx context.Context, b *bot.Bot, chatID int64, name string) {
	token, _, err := t.srv.CreateAgentToken(name)
	if err != nil {
		t.send(ctx, b, chatID, "生成注册令牌失败："+err.Error(), nil)
		return
	}
	command := t.srv.AgentInstallCommand(name, token)
	if command == "" {
		t.send(ctx, b, chatID, "注册令牌已生成，但无法确定 Server Host；请先在设置中配置。", nil)
		return
	}
	t.srv.log.Info("telegram privileged action", "action", "create_agent_token", "chat_id", chatID, "agent_name", name)
	t.send(ctx, b, chatID, "注意：Telegram Bot 私聊不是端到端加密。以下一次性注册令牌仅 10 分钟有效，请及时使用并删除消息。\n\n"+command, telegramHomeButton())
}

func (t *TelegramController) confirmAgentDelete(ctx context.Context, b *bot.Bot, chatID int64, agentID string) {
	agent := t.srv.st.State().Agents[agentID]
	if agent == nil {
		t.send(ctx, b, chatID, "未找到该 Agent。", nil)
		return
	}
	t.setPending(chatID, telegramPending{Kind: "delete-agent", RootDomain: agent.ID, ExpiresAt: time.Now().Add(2 * time.Minute)})
	markup := telegramKeyboard([][]models.InlineKeyboardButton{
		telegramRow(telegramButton("确认删除", "tg:del-agent-ok:"+agent.ID), telegramButton("取消", "tg:agent:"+agent.ID)),
	})
	t.send(ctx, b, chatID, "确认删除 Agent "+agent.Name+"？它将从所有证书的目标列表移除。", markup)
}

func (t *TelegramController) deleteAgent(ctx context.Context, b *bot.Bot, chatID int64, agentID string) {
	if !t.consumePendingAction(chatID, "delete-agent", agentID) {
		t.send(ctx, b, chatID, "删除确认已失效，请重新操作。", telegramHomeButton())
		return
	}
	if t.srv.st.State().Agents[agentID] == nil {
		t.send(ctx, b, chatID, "未找到该 Agent。", nil)
		return
	}
	t.srv.DeleteAgent(agentID)
	t.srv.log.Info("telegram privileged action", "action", "delete_agent", "chat_id", chatID, "agent_id", agentID)
	t.send(ctx, b, chatID, "Agent 已删除。", telegramHomeButton())
}

func (t *TelegramController) showCredentials(ctx context.Context, b *bot.Bot, chatID int64) {
	state := t.srv.st.State()
	credentials := make([]*domain.CloudflareCredential, 0, len(state.Credentials))
	for _, credential := range state.Credentials {
		if credential != nil {
			credentials = append(credentials, credential)
		}
	}
	sort.Slice(credentials, func(i, j int) bool { return credentials[i].Name < credentials[j].Name })
	t.send(ctx, b, chatID, telegramCredentialsText(credentials), telegramHomeButton())
}
