package server

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

// Web is the HTTP handler for the Web UI. It renders Go templates with HTMX
// for interactivity and enforces a single-admin login.
type Web struct {
	srv             *Server
	tmpl            *template.Template
	sessions        *sessionStore
	sourceLimiter   *sourceLimiter
	passwordGate    *workGate
	now             func() time.Time
	cookie          string
	authReadTimeout time.Duration
	authMu          sync.Mutex
	authWindow      time.Time
	authAttempts    int
}

// NewWeb builds the Web handler, parsing the embedded templates.
func NewWeb(s *Server) (*Web, error) {
	tmpl, err := parseWebTemplates()
	if err != nil {
		return nil, err
	}
	if s != nil {
		if err := s.initTwoFactorEncryption(); err != nil {
			return nil, err
		}
	}
	w := &Web{
		srv:             s,
		tmpl:            tmpl,
		sessions:        newSessionStore(),
		sourceLimiter:   newSourceLimiter(defaultSourceLimit, defaultSourceWindow, defaultSourceMaxEntries),
		passwordGate:    newWorkGate(defaultPasswordWorkSlots),
		now:             time.Now,
		cookie:          "omc_session",
		authReadTimeout: defaultAuthReadTimeout,
	}
	w.sessions.now = w.nowTime
	return w, nil
}

// nowTime is the single clock used by rate limiting, TOTP matching and session
// expiry. Tests replace w.now to advance time deterministically.
func (w *Web) nowTime() time.Time {
	if w != nil && w.now != nil {
		return w.now()
	}
	return time.Now()
}

// Handler returns the route mux (with auth middleware and static assets).
func (w *Web) Handler() http.Handler {
	mux := http.NewServeMux()
	// Static assets. Register with a method so it is unambiguous against the
	// method-specific catch-all "GET /" (much more specific path wins).
	fileSrv := http.FileServer(http.FS(mustSub(staticFS, "web/static")))
	mux.Handle("GET /static/", http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Cache-Control", "no-cache")
		http.StripPrefix("/static/", fileSrv).ServeHTTP(rw, r)
	}))

	mux.HandleFunc("GET /login", w.handleLoginPage)
	mux.HandleFunc("POST /login", w.handleLoginPost)
	mux.Handle("POST /logout", w.auth(w.handleLogout))
	mux.HandleFunc("POST /setup", w.handleSetup)

	// Protected routes.
	mux.Handle("GET /", w.auth(w.handleDashboard))
	mux.Handle("GET /certificates", w.auth(w.handleCertificates))
	mux.Handle("GET /certificates/new", w.auth(w.handleCertificateNew))
	mux.Handle("POST /certificates", w.auth(w.handleCertificateCreate))
	mux.Handle("GET /certificates/{id}/edit", w.auth(w.handleCertificateEdit))
	mux.Handle("POST /certificates/{id}", w.auth(w.handleCertificateUpdate))
	mux.Handle("POST /certificates/{id}/delete", w.auth(w.handleCertificateDelete))
	mux.Handle("POST /certificates/{id}/issue", w.auth(w.handleIssue))
	mux.Handle("GET /certificates/{id}/row", w.auth(w.handleCertificateRow))
	mux.Handle("GET /certificates/{id}/log", w.auth(w.handleCertificateLog))
	mux.Handle("GET /certificates/{id}/log/content", w.auth(w.handleCertificateLogContent))
	mux.Handle("POST /certificates/{id}/deploy", w.auth(w.handleDeploy))
	mux.Handle("GET /certificates/{id}/deploy", w.auth(w.handleDeployForm))

	mux.Handle("GET /credentials", w.auth(w.handleCredentials))
	mux.Handle("GET /credentials/new", w.auth(w.handleCredentialNew))
	mux.Handle("POST /credentials", w.auth(w.handleCredentialCreate))
	mux.Handle("GET /credentials/{id}/edit", w.auth(w.handleCredentialEdit))
	mux.Handle("POST /credentials/{id}", w.auth(w.handleCredentialUpdate))

	mux.Handle("GET /agents", w.auth(w.handleAgents))
	mux.Handle("POST /agents/token", w.auth(w.handleAgentToken))
	mux.Handle("POST /agents/update-all", w.auth(w.handleAgentUpdateAll))
	mux.Handle("POST /agents/{id}/update", w.auth(w.handleAgentUpdate))
	mux.Handle("POST /agents/{id}/delete", w.auth(w.handleAgentDelete))

	mux.Handle("GET /settings/2fa", w.auth(w.handleTwoFactorPage))
	mux.Handle("GET /settings/2fa/qr", w.auth(w.handleTwoFactorQR))
	mux.Handle("POST /settings/2fa/start", w.auth(w.handleTwoFactorStart))
	mux.Handle("POST /settings/2fa/enable", w.auth(w.handleTwoFactorEnable))
	mux.Handle("POST /settings/2fa/disable", w.auth(w.handleTwoFactorDisable))
	mux.Handle("GET /settings", w.auth(w.handleSettings))
	mux.Handle("POST /settings", w.auth(w.handleSettingsSave))
	mux.Handle("POST /settings/update", w.auth(w.handleServerUpdate))
	mux.Handle("POST /settings/ca", w.auth(w.handleCAAdd))
	mux.Handle("POST /settings/ca/{id}/default", w.auth(w.handleCADefault))

	return w.secure(mux)
}

// secure enforces same-origin on state-changing requests and sets hardening
// headers. It runs before authentication so login and bootstrap POSTs are
// covered too; requests without Origin/Referer (headless CLI and tests) pass.
func (w *Web) secure(child http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("X-Frame-Options", "DENY")
		rw.Header().Set("Referrer-Policy", "same-origin")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			rw.Header().Set("Cache-Control", "no-store")
		}
		if isMutatingMethod(r.Method) && !w.originAllowed(r) {
			http.Error(rw, "跨站请求被拒绝", http.StatusForbidden)
			return
		}
		child.ServeHTTP(rw, r)
	})
}

// --- auth middleware ---

// auth requires a live session and, for every state-changing method, a
// session-bound CSRF token. The token is read from the POST body or the
// X-CSRF-Token header; it is never accepted from the URL. The body is parsed
// here (bounded, with a read deadline) so handlers see a ready PostForm and a
// missing/wrong token is rejected before any side effect.
func (w *Web) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if _, ok := w.sessions.get(requestSession(r)); !ok {
			http.Redirect(rw, r, "/login", http.StatusFound)
			return
		}
		if isMutatingMethod(r.Method) {
			limit := int64(maxMutationBody)
			if strings.HasPrefix(r.URL.Path, "/settings/2fa/") {
				limit = maxTwoFactorBody
			}
			if !w.prepareBody(rw, r, limit) {
				return
			}
			// Re-read the session after the (possibly slow) body read. A
			// logout or 2FA rotation during that read revokes the old session;
			// validating against a pre-read snapshot would still let the
			// request write. The current token must match the current session.
			current, ok := w.sessions.get(requestSession(r))
			if !ok || !validCSRF(r, current) {
				http.Error(rw, "页面已过期，请刷新后重试", http.StatusForbidden)
				return
			}
		}
		next(rw, r)
	})
}

func (w *Web) sessionCookieAndSet(rw http.ResponseWriter, r *http.Request, id string) {
	http.SetCookie(rw, &http.Cookie{
		Name:     w.cookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   w.requestHTTPS(r),
		MaxAge:   int((24 * time.Hour).Seconds()),
	})
}

func requestSession(r *http.Request) string {
	c, err := r.Cookie("omc_session")
	if err != nil {
		return ""
	}
	return c.Value
}

// --- page rendering ---

type pageData struct {
	Title string
	Path  string
	Build any
}

func (w *Web) render(rw http.ResponseWriter, r *http.Request, name string, data any) error {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	return w.tmpl.ExecuteTemplate(rw, name, data)
}

// page renders a content fragment inside the shared layout shell. The fragment
// (e.g. "dashboard") is executed into a buffer and inserted as .Content. The
// session-bound CSRF token is injected into map/struct data and the layout so
// both normal forms and the layout logout form carry it.
func (w *Web) page(rw http.ResponseWriter, r *http.Request, title, path, fragment string, data any) error {
	csrf := ""
	switch d := data.(type) {
	case map[string]any:
		if existing, ok := d["CSRF"].(string); ok {
			csrf = existing
		}
		if csrf == "" {
			csrf = w.csrfForRequest(r)
			d["CSRF"] = csrf
		}
	case certificateForm:
		if d.CSRF == "" {
			d.CSRF = w.csrfForRequest(r)
		}
		data, csrf = d, d.CSRF
	case *certificateForm:
		if d != nil {
			if d.CSRF == "" {
				d.CSRF = w.csrfForRequest(r)
			}
			csrf = d.CSRF
		}
	}
	if csrf == "" {
		csrf = w.csrfForRequest(r)
	}
	var b strings.Builder
	if err := w.tmpl.ExecuteTemplate(&b, fragment, data); err != nil {
		w.srv.log.Error("render page fragment failed", "fragment", fragment, "err", err)
		http.Error(rw, "页面渲染失败，请查看 Server 日志", http.StatusInternalServerError)
		return err
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := w.tmpl.ExecuteTemplate(rw, "layout", map[string]any{
		"Title": title, "Path": path, "Content": template.HTML(b.String()), "CSRF": csrf,
	}); err != nil {
		w.srv.log.Error("render page layout failed", "fragment", fragment, "err", err)
		return err
	}
	return nil
}

// redirect navigates the browser to to. A plain form post gets the classic
// 302 + Location. An HTMX request instead gets HX-Redirect on a 204: HTMX
// follows a 3xx with the XHR itself and swaps the resulting full page into the
// element that triggered the request, so a redirect cannot be expressed as a
// 3xx. HX-Redirect tells htmx to set window.location and reload the whole page.
func (w *Web) redirect(rw http.ResponseWriter, r *http.Request, to string) {
	if r.Header.Get("HX-Request") == "true" {
		rw.Header().Set("HX-Redirect", to)
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(rw, r, to, http.StatusFound)
}

// --- login / setup ---

func (w *Web) handleLoginPage(rw http.ResponseWriter, r *http.Request) {
	if w.srv.setupPending() {
		w.render(rw, r, "login", map[string]any{"Setup": true})
		return
	}
	w.render(rw, r, "login", map[string]any{"TwoFactorEnabled": w.srv.getAdmin().TwoFactor.Enabled})
}

func (w *Web) handleLoginPost(rw http.ResponseWriter, r *http.Request) {
	// The body is bounded and parsed before authMu: a slow or oversized client
	// must never hold the lock that serializes OTP consumption and sessions.
	if !w.prepareBody(rw, r, maxLoginBody) {
		return
	}
	// Source limiting runs first and is the only quota a wrong password
	// consumes. Anonymous password guessing therefore cannot exhaust the
	// administrator's account-wide second-factor budget.
	if !w.allowSourceAttempt(rw, r) {
		return
	}
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	otp := r.PostForm.Get("otp")

	// Capture the revocation epoch before reading the account and verifying
	// the password. If a 2FA enable/disable rotates sessions while we are
	// verifying, this login must not resurrect a session afterwards.
	generation := w.sessions.currentGeneration()

	admin := w.srv.getAdmin()
	if !admin.SetupTokenUsed {
		w.redirect(rw, r, "/login")
		return
	}

	// Password verification is deliberately outside authMu, but it runs under a
	// small global work gate so concurrent Argon2 calls cannot exhaust memory.
	passwordOK, ok := w.verifyPasswordGated(rw, password, admin.PasswordHash)
	if !ok {
		return
	}
	if admin.Username != username || !passwordOK {
		if err := w.recordAdminLogin(r, username, false); err != nil {
			w.srv.log.Error("persist admin login failed", "err", err)
			http.Error(rw, "无法保存登录记录，请稍后重试", http.StatusInternalServerError)
			return
		}
		w.renderLoginFailure(rw, r, admin)
		return
	}

	id, ok := w.commitLogin(rw, r, username, admin, generation, otp)
	if !ok {
		return
	}
	w.sessionCookieAndSet(rw, r, id)
	w.redirect(rw, r, "/")
}

// commitLogin is the single critical section that re-checks the account and
// revocation epoch, consumes the second factor, persists the login record and
// creates the session. The request body is already parsed, so nothing here
// reads from the client. It returns ok=false when it has already written a
// response (failure, rate limit or a revocation that raced the login).
func (w *Web) commitLogin(rw http.ResponseWriter, r *http.Request, username string, admin domain.AdminAccount, generation uint64, otp string) (string, bool) {
	w.authMu.Lock()
	current := w.srv.getAdmin()
	if current.PasswordHash != admin.PasswordHash ||
		current.TwoFactor.Enabled != admin.TwoFactor.Enabled ||
		w.sessions.currentGeneration() != generation {
		w.authMu.Unlock()
		if err := w.recordAdminLogin(r, username, false); err != nil {
			w.srv.log.Error("persist admin login failed", "err", err)
			http.Error(rw, "无法保存登录记录，请稍后重试", http.StatusInternalServerError)
			return "", false
		}
		w.renderLoginFailure(rw, r, current)
		return "", false
	}
	success := true
	if current.TwoFactor.Enabled {
		// Only a correct password reaches the account-wide quota; it bounds
		// OTP/recovery guessing, not anonymous password attempts.
		if !w.allowSensitiveAttempt(rw) {
			w.authMu.Unlock()
			return "", false
		}
		var err error
		success, err = w.consumeSecondFactor(otp)
		if err != nil {
			w.authMu.Unlock()
			w.srv.log.Error("persist second factor failed", "err", err)
			http.Error(rw, "验证失败，请稍后重试", http.StatusInternalServerError)
			return "", false
		}
	}
	if err := w.recordAdminLogin(r, username, success); err != nil {
		w.authMu.Unlock()
		w.srv.log.Error("persist admin login failed", "err", err)
		http.Error(rw, "无法保存登录记录，请稍后重试", http.StatusInternalServerError)
		return "", false
	}
	if !success {
		w.authMu.Unlock()
		w.renderLoginFailure(rw, r, current)
		return "", false
	}
	id := w.sessions.create(username)
	w.authMu.Unlock()
	return id, true
}

func (w *Web) renderLoginFailure(rw http.ResponseWriter, r *http.Request, admin domain.AdminAccount) {
	message := "用户名或密码错误"
	if admin.TwoFactor.Enabled {
		message = "用户名、密码或验证码错误；已使用的验证码不可重复使用"
	}
	w.render(rw, r, "login", map[string]any{"Error": message, "TwoFactorEnabled": admin.TwoFactor.Enabled})
}

func (w *Web) handleSetup(rw http.ResponseWriter, r *http.Request) {
	if !w.prepareBody(rw, r, maxSetupBody) {
		return
	}
	if !w.allowSourceAttempt(rw, r) {
		return
	}
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	username, err := validateAdminCredentials(username, password)
	if err != nil {
		w.render(rw, r, "login", map[string]any{"Error": err.Error(), "Setup": true})
		return
	}
	// The first-admin hash is expensive too; gate it like password checks.
	release, ok := w.acquirePasswordWork(rw)
	if !ok {
		return
	}
	hash, err := hashPassword(password)
	release()
	if err != nil {
		http.Error(rw, "无法初始化管理员账户，请稍后重试", http.StatusInternalServerError)
		return
	}
	if err := w.srv.setupAdminWithHash(username, hash, r.PostForm.Get("setup_token")); err != nil {
		w.render(rw, r, "login", map[string]any{"Error": err.Error(), "Setup": true})
		return
	}
	w.redirect(rw, r, "/login")
}

func (w *Web) handleLogout(rw http.ResponseWriter, r *http.Request) {
	id := requestSession(r)
	w.sessions.delete(id)
	http.SetCookie(rw, &http.Cookie{
		Name: w.cookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: w.requestHTTPS(r),
	})
	w.redirect(rw, r, "/login")
}

// --- dashboard ---

func (w *Web) handleDashboard(rw http.ResponseWriter, r *http.Request) {
	st := w.srv.st.State()
	failures := []map[string]string{}
	for _, c := range st.Certificates {
		if c.LastError != "" {
			failures = append(failures, map[string]string{
				"Domain": c.RootDomain, "Kind": "issue",
				"When": c.CreatedAt.Format("2006-01-02 15:04"), "Message": c.LastError,
			})
		}
		for _, agentID := range c.TargetAgents {
			d := c.Deploys[agentID]
			if d == nil || d.Status != domain.StatusFailed || d.Error == "" {
				continue
			}
			name := agentID
			if agent := st.Agents[agentID]; agent != nil && agent.Name != "" {
				name = agent.Name
			}
			when := d.LastAttemptAt.Format("2006-01-02 15:04")
			failures = append(failures, map[string]string{
				"Domain": c.RootDomain, "Kind": "deploy",
				"When": when, "Message": name + "：" + d.Error,
			})
		}
	}
	stats := map[string]int{
		"Certs": 0, "Issued": 0, "Agents": 0, "Credentials": 0,
	}
	stats["Certs"] = len(st.Certificates)
	for _, c := range st.Certificates {
		if c.Current != nil {
			stats["Issued"]++
		}
	}
	stats["Agents"] = len(st.Agents)
	stats["Credentials"] = len(st.Credentials)
	w.page(rw, r, "概览", "/", "dashboard", map[string]any{
		"Stats": stats, "Failures": failures,
	})
}

// --- certificates ---

func (w *Web) handleCertificates(rw http.ResponseWriter, r *http.Request) {
	st := w.srv.st.State()
	rows := make([]certificateRow, 0, len(st.Certificates))
	for _, cert := range st.Certificates {
		rows = append(rows, makeCertificateRow(cert))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].RootDomain < rows[j].RootDomain })
	w.page(rw, r, "证书", "/certificates", "certificates", map[string]any{"Certs": rows})
}

func (w *Web) handleCertificateNew(rw http.ResponseWriter, r *http.Request) {
	w.page(rw, r, "新建证书", "/certificates", "certnew", w.certificateForm(w.srv.st.State(), nil))
}

func (w *Web) handleCertificateEdit(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cert := w.srv.st.State().Certificates[id]
	if cert == nil {
		writeJSONErr(rw, http.StatusNotFound, "certificate not found")
		return
	}
	w.page(rw, r, "编辑证书", "/certificates", "certnew", w.certificateForm(w.srv.st.State(), cert))
}

func (w *Web) handleCertificateUpdate(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	enabled := r.PostForm.Get("enabled") == "on"
	err := w.srv.UpdateCertificate(r.PathValue("id"), r.PostForm.Get("root"), r.PostForm.Get("credential_id"),
		r.PostForm.Get("acme_id"), domain.KeyType(r.PostForm.Get("key_type")), enabled, r.PostForm["agents"])
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeJSONErr(rw, http.StatusNotFound, "certificate not found")
			return
		}
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	w.redirect(rw, r, "/certificates")
}

func (w *Web) handleCertificateDelete(rw http.ResponseWriter, r *http.Request) {
	if err := w.srv.DeleteCertificate(r.PathValue("id")); err != nil {
		if errors.Is(err, errNotFound) {
			writeJSONErr(rw, http.StatusNotFound, "certificate not found")
			return
		}
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	w.redirect(rw, r, "/certificates")
}

func (w *Web) handleCertificateCreate(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	agents := r.PostForm["agents"]
	if _, err := w.srv.CreateCertificate(
		r.PostForm.Get("root"), r.PostForm.Get("credential_id"), r.PostForm.Get("acme_id"),
		domain.KeyType(r.PostForm.Get("key_type")), agents,
	); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	w.redirect(rw, r, "/certificates")
}

func (w *Web) handleIssue(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, _, err := w.srv.StartIssue(id, taskTypeIssue); err != nil {
		status := http.StatusBadRequest
		msg := err.Error()
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
			msg = "certificate not found"
		} else if errors.Is(err, errCertDeploying) {
			status = http.StatusConflict
		}
		writeJSONErr(rw, status, msg)
		return
	}
	w.renderCertificateRow(rw, id)
}

func (w *Web) handleCertificateRow(rw http.ResponseWriter, r *http.Request) {
	w.renderCertificateRow(rw, r.PathValue("id"))
}

func (w *Web) handleCertificateLog(rw http.ResponseWriter, r *http.Request) {
	data, ok := w.certificateLogData(rw, r.PathValue("id"))
	if !ok {
		return
	}
	w.page(rw, r, "签发日志", "/certificates", "certificate-log", data)
}

func (w *Web) handleCertificateLogContent(rw http.ResponseWriter, r *http.Request) {
	data, ok := w.certificateLogData(rw, r.PathValue("id"))
	if !ok {
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := w.tmpl.ExecuteTemplate(rw, "certificate-log-content", data); err != nil {
		w.srv.log.Error("render certificate log failed", "cert_id", r.PathValue("id"), "err", err)
	}
}

func (w *Web) certificateLogData(rw http.ResponseWriter, id string) (map[string]any, bool) {
	cert := w.srv.st.State().Certificates[id]
	if cert == nil {
		writeJSONErr(rw, http.StatusNotFound, "certificate not found")
		return nil, false
	}
	logText, err := w.srv.st.ReadCertificateLog(id)
	if err != nil {
		writeJSONErr(rw, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	deploys := make([]certificateDeployLog, 0, len(cert.TargetAgents))
	for _, agentID := range cert.TargetAgents {
		name := agentID
		if agent := w.srv.st.State().Agents[agentID]; agent != nil && agent.Name != "" {
			name = agent.Name
		}
		state := cert.Deploys[agentID]
		status := domain.OperationStatus("")
		nginx, errText, lastLog := "", "", ""
		if state != nil {
			status = state.Status
			nginx = state.NginxStatus
			errText = state.Error
			lastLog = state.LastLog
		}
		fileLog, err := w.srv.st.ReadAgentDeployLog(id, agentID)
		if err != nil {
			writeJSONErr(rw, http.StatusInternalServerError, err.Error())
			return nil, false
		}
		if strings.TrimSpace(fileLog) != "" {
			lastLog = fileLog
		}
		deploys = append(deploys, certificateDeployLog{
			Name: name, Status: string(status), StatusLabel: deployStatusLabel(status),
			NginxStatus: nginx, Error: errText, Log: lastLog,
		})
	}
	return map[string]any{
		"ID": id, "RootDomain": cert.RootDomain, "Log": logText, "Deploys": deploys,
		"Running": certificateBusy(cert),
	}, true
}

func (w *Web) handleDeployForm(rw http.ResponseWriter, r *http.Request) {
	st := w.srv.st.State()
	cert := st.Certificates[r.PathValue("id")]
	if cert == nil {
		writeJSONErr(rw, http.StatusNotFound, "certificate not found")
		return
	}
	row := makeCertificateRow(cert)
	if !row.CanDeploy {
		writeJSONErr(rw, http.StatusConflict, row.DeployDisabledReason)
		return
	}
	type option struct {
		ID, Name, Address string
		Available         bool
	}
	agents := make([]option, 0, len(cert.TargetAgents))
	for _, id := range cert.TargetAgents {
		a := option{ID: id, Name: id}
		if agent := st.Agents[id]; agent != nil {
			a.Name = agentLabel(agent)
			a.Address = agent.Address
			a.Available = true
		}
		agents = append(agents, a)
	}
	_ = w.render(rw, r, "certificate-deploy-form", map[string]any{
		"ID": cert.ID, "RootDomain": cert.RootDomain, "Agents": agents,
		"CSRF": w.csrfForRequest(r),
	})
}

func (w *Web) handleDeploy(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	started, err := w.srv.StartDeployToAgents(id, r.PostForm["agents"])
	if err != nil {
		status := http.StatusBadRequest
		msg := err.Error()
		switch {
		case errors.Is(err, errNotFound):
			status = http.StatusNotFound
			msg = "certificate not found"
		case errors.Is(err, errCertNotIssued), errors.Is(err, errNoTargetAgents), errors.Is(err, errNoSelectedAgents):
			status = http.StatusUnprocessableEntity
		case errors.Is(err, errCertIssuing), errors.Is(err, errInvalidTargetAgent), errors.Is(err, errTargetAgentRemoved):
			status = http.StatusConflict
		}
		writeJSONErr(rw, status, msg)
		return
	}
	if started {
		setToastTrigger(rw, "已开始异步下发到目标 Agent", "success")
	} else {
		setToastTrigger(rw, "该证书已有下发任务正在运行", "success")
	}
	w.renderCertificateRow(rw, id)
}

func setToastTrigger(rw http.ResponseWriter, message, toastType string) {
	// Response headers are not guaranteed to preserve raw UTF-8 through every
	// proxy/browser stack. Quote strings as ASCII JSON escapes so HTMX's
	// JSON.parse reconstructs the original Unicode message without mojibake.
	trigger := `{"showToast":{"message":` + strconv.QuoteToASCII(message) +
		`,"type":` + strconv.QuoteToASCII(toastType) + `}}`
	rw.Header().Set("HX-Trigger", trigger)
}

func certificateDeploymentComplete(cert *domain.Certificate) bool {
	if cert == nil {
		return false
	}
	return certificateDeploymentCompleteForAgents(cert, cert.TargetAgents)
}

func certificateDeploymentCompleteForAgents(cert *domain.Certificate, agents []string) bool {
	if cert == nil || cert.Current == nil || len(agents) == 0 {
		return false
	}
	for _, agentID := range agents {
		deploy := cert.Deploys[agentID]
		if deploy == nil || deploy.Status != domain.StatusSuccess || deploy.VersionID != cert.Current.ID {
			return false
		}
	}
	return true
}

func (w *Web) renderCertificateRow(rw http.ResponseWriter, id string) {
	cert := w.srv.st.State().Certificates[id]
	if cert == nil {
		writeJSONErr(rw, http.StatusNotFound, "certificate not found")
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := w.tmpl.ExecuteTemplate(rw, "certificate-row", makeCertificateRow(cert)); err != nil {
		w.srv.log.Error("render certificate row failed", "cert_id", id, "err", err)
	}
}

// --- credentials ---

func (w *Web) handleCredentials(rw http.ResponseWriter, r *http.Request) {
	st := w.srv.st.State()
	type row struct {
		ID, Name, ZoneID, AccountID, TokenMasked string
		Enabled                                  bool
	}
	rows := []row{}
	for _, c := range st.Credentials {
		rows = append(rows, row{c.ID, c.Name, c.ZoneID, c.AccountID, MaskedToken(c.Token), c.Enabled})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	w.page(rw, r, "凭据", "/credentials", "credentials", map[string]any{"Creds": rows})
}

func (w *Web) handleCredentialNew(rw http.ResponseWriter, r *http.Request) {
	w.page(rw, r, "新增凭据", "/credentials", "credform", map[string]any{"Editing": nil})
}

func (w *Web) handleCredentialCreate(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if _, err := w.srv.CreateCredential(
		r.PostForm.Get("name"), r.PostForm.Get("token"), r.PostForm.Get("zone_id"),
		r.PostForm.Get("account_id"), r.PostForm.Get("remark"),
	); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	w.redirect(rw, r, "/credentials")
}

func (w *Web) handleCredentialEdit(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c := w.srv.st.State().Credentials[id]
	w.page(rw, r, "编辑凭据", "/credentials", "credform", map[string]any{
		"Editing": map[string]any{
			"ID": c.ID, "Name": c.Name, "ZoneID": c.ZoneID, "AccountID": c.AccountID,
			"Remark": c.Remark, "Enabled": c.Enabled, "TokenMasked": MaskedToken(c.Token),
		},
	})
}

func (w *Web) handleCredentialUpdate(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	r.ParseForm()
	enabled := r.PostForm.Get("enabled") == "on"
	err := w.srv.UpdateCredential(id, r.PostForm.Get("name"), r.PostForm.Get("token"),
		r.PostForm.Get("zone_id"), r.PostForm.Get("account_id"), r.PostForm.Get("remark"), enabled)
	if err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	w.redirect(rw, r, "/credentials")
}

// --- agents ---

// agentsPageTimeout bounds the single shared release-catalog query behind one
// /agents render. It is applied once for the whole page, never per Agent.
const agentsPageTimeout = 12 * time.Second

// agentRow is one rendered row of the Agent table. VersionHint explains why no
// upgrade options are shown (catalog/health/platform error, or because this
// response deliberately did not query the release catalog).
type agentRow struct {
	ID, Name, Addr, Status, StatusLabel, Version, Platform, CertExpiresAt string
	UpdateStatus, UpdateTarget, UpdateError, VersionHint                  string
	Versions                                                              []string
	DefaultVersion                                                        string
}

// agentCertificateOption is one selectable certificate in the registration
// form. Only the root domain is shown; the ID remains the submitted value.
type agentCertificateOption struct {
	ID, RootDomain string
}

func (w *Web) handleAgents(rw http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), agentsPageTimeout)
	defer cancel()
	versions, catalogErr := w.srv.AllAgentVersions(ctx)
	data := w.agentsPageData(versions, true)
	if catalogErr != nil {
		data["CatalogError"] = catalogErr.Error()
		data["UpdateAllHint"] = "无法获取 GitHub 发布目录，暂时无法批量更新。"
	}
	w.page(rw, r, "Agent", "/agents", "agents", data)
}

func (w *Web) handleAgentToken(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	name := r.PostForm.Get("name")
	selected := r.PostForm["certificates"]
	token, _, err := w.srv.CreateAgentTokenWithCertificates(name, selected)
	data := w.agentsPageData(nil, false)
	data["Name"] = name
	data["SelectedCertificates"] = certificateSelection(selected)
	if err != nil {
		data["TokenError"] = err.Error()
		w.page(rw, r, "Agent", "/agents", "agents", data)
		return
	}
	data["InstallCommand"] = w.srv.AgentInstallCommandWithSudo(name, token, true)
	data["InstallCommandNoSudo"] = w.srv.AgentInstallCommandWithSudo(name, token, false)
	w.page(rw, r, "Agent", "/agents", "agents", data)
}

func (w *Web) handleAgentUpdateAll(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	// The batch target is chosen by the Server from its own catalog snapshot;
	// any client-supplied version/target fields are intentionally ignored.
	started, skipped, err := w.srv.StartAllAgentUpdates()
	data := w.agentsPageData(nil, false)
	if started > 0 || skipped > 0 {
		notice := fmt.Sprintf("已启动 %d 台，跳过 %d 台。", started, skipped)
		if started == 0 {
			notice += "没有可更新的 Agent。"
		}
		data["Notice"] = notice
	}
	if err != nil {
		data["NoticeError"] = err.Error()
	}
	w.page(rw, r, "Agent", "/agents", "agents", data)
}

func (w *Web) handleAgentUpdate(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	if err := w.srv.StartAgentUpdate(r.PathValue("id"), r.PostForm.Get("version")); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	w.redirect(rw, r, "/agents")
}

func (w *Web) handleAgentDelete(rw http.ResponseWriter, r *http.Request) {
	w.srv.DeleteAgent(r.PathValue("id"))
	w.redirect(rw, r, "/agents")
}

// agentsPageData builds the shared /agents payload. versions may be nil when a
// response must not trigger a release-catalog query (token creation and batch
// update feedback); rows then explain that a refresh is needed before per-Agent
// upgrades can be offered.
func (w *Web) agentsPageData(versions map[string]AgentVersionOptions, loaded bool) map[string]any {
	rows := w.agentRows(versions, loaded)
	data := map[string]any{
		"Agents":               rows,
		"Certificates":         w.agentCertificateOptions(),
		"SelectedCertificates": map[string]bool{},
		"Name":                 "",
		"ServerVersion":        Version,
		"CanUpdateAll":         false,
		"UpdateCandidateCount": 0,
		"UpdateCandidateNames": "",
	}
	if !loaded {
		return data
	}
	candidates := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.UpdateStatus == string(domain.StatusRunning) || len(row.Versions) == 0 {
			continue
		}
		candidates = append(candidates, row.Name)
	}
	data["CanUpdateAll"] = len(candidates) > 0
	data["UpdateCandidateCount"] = len(candidates)
	data["UpdateCandidateNames"] = strings.Join(candidates, "、")
	if len(rows) > 0 && len(candidates) == 0 {
		data["UpdateAllHint"] = "当前没有可更新的 Agent（均已是最新、正在更新或不可用）。"
	}
	return data
}

func (w *Web) agentRows(versions map[string]AgentVersionOptions, loaded bool) []agentRow {
	st := w.srv.st.State()
	ids := make([]string, 0, len(st.Agents))
	for id := range st.Agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := make([]agentRow, 0, len(ids))
	for _, id := range ids {
		a := st.Agents[id]
		if a == nil {
			continue
		}
		statusLabel := map[domain.AgentStatus]string{
			domain.AgentRegistered: "已注册", domain.AgentUnreachable: "不可达",
			domain.AgentDisabled: "已禁用", domain.AgentUnregistered: "未注册",
		}[a.Status]
		expiresAt := "—"
		if !a.CertExpiresAt.IsZero() {
			expiresAt = a.CertExpiresAt.Format("2006-01-02")
		}
		platform := "—"
		if a.GOOS != "" && a.GOARCH != "" {
			platform = a.GOOS + "/" + a.GOARCH
		}
		row := agentRow{
			ID: a.ID, Name: a.Name, Addr: a.Address + ":" + strconv.Itoa(a.Port),
			Status: string(a.Status), StatusLabel: statusLabel, Version: a.Version,
			Platform: platform, CertExpiresAt: expiresAt,
			UpdateStatus: string(a.UpdateStatus), UpdateTarget: a.UpdateTargetVersion,
			UpdateError: a.UpdateError,
		}
		if loaded {
			// An Agent registered while the shared check was running has no
			// entry in this snapshot. Its zero value must not be mistaken for
			// "already up to date", so require an explicit presence check.
			option, checked := versions[id]
			if !checked {
				row.VersionHint = "尚未检查版本，请刷新后重试"
			} else {
				row.Versions = option.Versions
				if option.Err != nil {
					row.VersionHint = option.Err.Error()
				}
				if containsString(option.Versions, Version) {
					row.DefaultVersion = Version
				} else if len(option.Versions) > 0 {
					row.DefaultVersion = option.Versions[0]
				}
			}
		} else {
			row.VersionHint = "刷新页面后获取可用版本"
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].ID < rows[j].ID
	})
	return rows
}

func (w *Web) agentCertificateOptions() []agentCertificateOption {
	st := w.srv.st.State()
	options := make([]agentCertificateOption, 0, len(st.Certificates))
	for _, cert := range st.Certificates {
		if cert == nil {
			continue
		}
		options = append(options, agentCertificateOption{ID: cert.ID, RootDomain: cert.RootDomain})
	}
	sort.SliceStable(options, func(i, j int) bool {
		if options[i].RootDomain != options[j].RootDomain {
			return options[i].RootDomain < options[j].RootDomain
		}
		return options[i].ID < options[j].ID
	})
	return options
}

func certificateSelection(ids []string) map[string]bool {
	selected := make(map[string]bool, len(ids))
	for _, id := range ids {
		selected[id] = true
	}
	return selected
}

// --- settings ---

func (w *Web) handleSettings(rw http.ResponseWriter, r *http.Request) {
	st := w.srv.st.State()
	cas := []map[string]any{}
	for _, c := range st.CAs {
		cas = append(cas, map[string]any{
			"ID": c.ID, "Name": c.Name, "DirectoryURL": c.DirectoryURL,
			"Builtin": c.Builtin, "Default": c.ID == st.Config.DefaultACMEID,
		})
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	versions, versionErr := w.srv.ServerVersions(ctx)
	cancel()
	update := w.srv.SelfUpdate()
	updateHint := ""
	if versionErr != nil {
		updateHint = versionErr.Error()
	}
	hostHint := ""
	if ips, err := serverIPs(); err == nil && len(ips) > 0 {
		hostHint = ips[0].String()
	}
	tgTokenMasked := ""
	if st.Config.TelegramToken != "" {
		tgTokenMasked = MaskedToken(st.Config.TelegramToken)
	}
	tgStatus, tgError := w.srv.TelegramRuntimeStatus()
	w.page(rw, r, "设置", "/settings", "settings", map[string]any{
		"AdminLogins":      st.AdminLogins,
		"TwoFactorEnabled": st.Admin.TwoFactor.Enabled,
		"CAs":              cas, "Email": st.Config.ACMEAccountEmail,
		"RenewDays": st.Config.RenewPreferenceDays, "DNSSleep": st.Config.DNSSleepSeconds,
		"ServerHost": st.Config.ServerHost, "HostHint": hostHint,
		"TGEnabled": st.Config.TelegramEnabled, "TGTokenSet": st.Config.TelegramToken != "",
		"TGTokenMasked": tgTokenMasked, "TGChatID": st.Config.TelegramChatID,
		"TGStatus": tgStatus, "TGError": tgError,
		"ServerVersion": Version, "ServerVersions": versions, "UpdateHint": updateHint,
		"UpdateStatus": string(update.Status), "UpdateTarget": update.Target, "UpdateError": update.Error,
	})
}

func (w *Web) handleServerUpdate(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	if err := w.srv.StartSelfUpdate(r.PostForm.Get("version")); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	w.redirect(rw, r, "/settings")
}

func (w *Web) handleSettingsSave(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, "invalid settings form")
		return
	}
	chatID, err := parseTelegramChatID(r.PostForm.Get("tg_chat_id"))
	if err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	current := w.srv.st.State().Config
	tgToken := strings.TrimSpace(r.PostForm.Get("tg_token"))
	tgEnabled := r.PostForm.Get("tg_enabled") == "on"
	tgClearToken := r.PostForm.Get("tg_clear_token") == "on"
	if tgClearToken && tgEnabled {
		writeJSONErr(rw, http.StatusBadRequest, "请先关闭 Telegram 机器人再清除 Token")
		return
	}
	effectiveToken := tgToken
	if effectiveToken == "" && !tgClearToken {
		effectiveToken = current.TelegramToken
	}
	if tgEnabled && effectiveToken == "" {
		writeJSONErr(rw, http.StatusBadRequest, "启用 Telegram 机器人前必须配置 Bot Token")
		return
	}
	if tgEnabled && !validTelegramBotToken(effectiveToken) {
		writeJSONErr(rw, http.StatusBadRequest, "Telegram Bot Token 格式无效")
		return
	}

	// Changing the bot token or the authorized private-chat user is a
	// credential change: require the current password and, when enabled, a
	// one-time 2FA code. Other settings can be saved without re-authentication.
	if telegramConfigChanged(current, tgToken, tgClearToken, chatID, tgEnabled) && !w.verifyReauthentication(rw, r) {
		return
	}

	renewDays, _ := strconv.Atoi(r.PostForm.Get("renew_days"))
	dnsSleep, _ := strconv.Atoi(r.PostForm.Get("dns_sleep"))
	if err := w.srv.st.Update(func(st *domain.State) error {
		st.Config.ACMEAccountEmail = strings.TrimSpace(r.PostForm.Get("email"))
		st.Config.ServerHost = strings.TrimSpace(r.PostForm.Get("server_host"))
		if renewDays > 0 {
			st.Config.RenewPreferenceDays = renewDays
		}
		st.Config.DNSSleepSeconds = dnsSleep
		st.Config.TelegramEnabled = tgEnabled
		if tgClearToken {
			st.Config.TelegramToken = ""
		} else if tgToken != "" {
			st.Config.TelegramToken = tgToken
		}
		st.Config.TelegramChatID = chatID
		return nil
	}); err != nil {
		writeJSONErr(rw, http.StatusInternalServerError, "保存设置失败")
		return
	}
	w.srv.TelegramReset()
	w.redirect(rw, r, "/settings")
}

// telegramConfigChanged reports whether a settings submission changes the bot
// token, the authorized private-chat user, or the enabled state. Stopping the
// bot or activating a stored credential is a sensitive control change too, so
// all three require re-authentication.
func telegramConfigChanged(current domain.SystemConfig, token string, clear bool, chatID int64, enabled bool) bool {
	tokenChanged := (clear && current.TelegramToken != "") ||
		(token != "" && token != current.TelegramToken)
	return tokenChanged || chatID != current.TelegramChatID || enabled != current.TelegramEnabled
}

// verifyReauthentication confirms the current password and, when 2FA is
// enabled, consumes a one-time code. The password is checked outside authMu;
// only the one-time factor consumption and its account quota take the lock.
func (w *Web) verifyReauthentication(rw http.ResponseWriter, r *http.Request) bool {
	if !w.allowSourceAttempt(rw, r) {
		return false
	}
	admin := w.srv.getAdmin()
	passwordOK, ok := w.verifyPasswordGated(rw, r.PostForm.Get("password"), admin.PasswordHash)
	if !ok {
		return false
	}
	if !passwordOK {
		http.Error(rw, "修改 Telegram 配置需要验证当前密码", http.StatusForbidden)
		return false
	}
	if !admin.TwoFactor.Enabled {
		return true
	}
	w.authMu.Lock()
	defer w.authMu.Unlock()
	current := w.srv.getAdmin()
	if !current.TwoFactor.Enabled || current.PasswordHash != admin.PasswordHash {
		http.Error(rw, "账户状态已变化，请重试", http.StatusForbidden)
		return false
	}
	if !w.allowSensitiveAttempt(rw) {
		return false
	}
	ok, err := w.consumeSecondFactor(r.PostForm.Get("otp"))
	if err != nil {
		http.Error(rw, "验证失败，请稍后重试", http.StatusInternalServerError)
		return false
	}
	if !ok {
		http.Error(rw, "密码或验证码错误", http.StatusForbidden)
		return false
	}
	return true
}

func validTelegramBotToken(token string) bool {
	botID, secret, ok := strings.Cut(strings.TrimSpace(token), ":")
	if !ok || botID == "" || len(secret) < 20 {
		return false
	}
	for _, char := range botID {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func parseTelegramChatID(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	chatID, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, errors.New("Telegram 用户 ID 必须是整数")
	}
	if chatID < 0 {
		return 0, errors.New("Telegram 仅支持私聊用户 ID，不能使用群组 Chat ID")
	}
	return chatID, nil
}

func (w *Web) handleCAAdd(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	id, _ := newID()
	_ = w.srv.st.WithState(true, func(st *domain.State) error {
		st.CAs[id] = &domain.ACMECA{
			ID: id, Name: r.PostForm.Get("name"), DirectoryURL: r.PostForm.Get("directory_url"),
			Enabled: true, CreatedAt: time.Now(),
		}
		return nil
	})
	w.redirect(rw, r, "/settings")
}

func (w *Web) handleCADefault(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_ = w.srv.st.WithState(true, func(st *domain.State) error {
		st.Config.DefaultACMEID = id
		return nil
	})
	w.redirect(rw, r, "/settings")
}

// --- helpers ---

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

func newID() (string, error) { return store.NewID() }

type certificateRow struct {
	ID                   string
	RootDomain           string
	IssueStatus          string
	IssueStatusLabel     string
	IssuedAt             string
	ExpiresAt            string
	KeyType              string
	LastError            string
	DeployError          string
	Issuing              bool
	Deploying            bool
	Running              bool
	CanDeploy            bool
	DeployDisabledReason string
}

type certificateDeployLog struct {
	Name, Status, StatusLabel, NginxStatus, Error, Log string
}

// certificateForm holds the data shared by the new/edit certificate form. The
// same template renders both: .Edit distinguishes the two, and .Selected carries
// the already-targeted agents so the multi-select can pre-check them.
type certificateForm struct {
	Edit         bool
	ID           string
	RootDomain   string
	CredentialID string
	ACMEID       string
	KeyType      string
	Enabled      bool
	CSRF         string
	Selected     map[string]bool
	Credentials  []credOption
	CAs          []caView
	Agents       []agentView
}

// credOption is a Cloudflare credential option in the certificate form.
type credOption struct{ ID, Name string }

// caView is an ACME CA option; Default is the config-level default CA.
type caView struct {
	ID, Name string
	Default  bool
}

// agentView is an Agent option in the certificate form.
type agentView struct{ ID, Name, Address string }

func (w *Web) certificateForm(st domain.State, cert *domain.Certificate) certificateForm {
	form := certificateForm{
		Credentials: []credOption{}, CAs: []caView{}, Agents: []agentView{},
		Selected: map[string]bool{},
	}
	for _, c := range st.Credentials {
		form.Credentials = append(form.Credentials, credOption{ID: c.ID, Name: c.Name})
	}
	for _, c := range st.CAs {
		form.CAs = append(form.CAs, caView{ID: c.ID, Name: c.Name, Default: c.ID == st.Config.DefaultACMEID})
	}
	for _, a := range st.Agents {
		form.Agents = append(form.Agents, agentView{ID: a.ID, Name: a.Name, Address: a.Address})
	}
	if cert != nil {
		form.Edit = true
		form.ID = cert.ID
		form.RootDomain = cert.RootDomain
		form.CredentialID = cert.CredentialID
		form.ACMEID = cert.ACMEID
		form.KeyType = string(cert.KeyType)
		form.Enabled = cert.Enabled
		for _, aid := range cert.TargetAgents {
			form.Selected[aid] = true
		}
	}
	return form
}

func makeCertificateRow(cert *domain.Certificate) certificateRow {
	label := map[domain.OperationStatus]string{
		domain.StatusPending: "待签发", domain.StatusRunning: "签发中",
		domain.StatusSuccess: "已签发", domain.StatusFailed: "失败",
	}[cert.IssueStatus]
	expiresAt := "—"
	issuedAt := "—"
	if cert.Current != nil {
		issuedAt = cert.Current.IssuedAt.Format("2006-01-02")
		expiresAt = cert.Current.ExpiresAt.Format("2006-01-02")
	}
	issuing := cert.IssueStatus == domain.StatusRunning
	deploying := cert.DeployStatus == domain.StatusRunning
	canDeploy := cert.Current != nil && len(cert.TargetAgents) > 0 && !issuing && !deploying
	disabledReason := ""
	if cert.Current == nil {
		disabledReason = "请先签发证书"
	} else if issuing {
		disabledReason = "证书正在签发"
	} else if deploying {
		disabledReason = "证书正在下发"
	} else if len(cert.TargetAgents) == 0 {
		disabledReason = "未配置目标 Agent"
	}
	return certificateRow{
		ID: cert.ID, RootDomain: cert.RootDomain,
		IssueStatus: string(cert.IssueStatus), IssueStatusLabel: label,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, KeyType: string(cert.KeyType),
		LastError: cert.LastError, DeployError: certificateDeployError(cert),
		Issuing: issuing, Deploying: deploying, Running: issuing || deploying, CanDeploy: canDeploy,
		DeployDisabledReason: disabledReason,
	}
}

func certificateBusy(cert *domain.Certificate) bool {
	return cert != nil && (cert.IssueStatus == domain.StatusRunning || cert.DeployStatus == domain.StatusRunning)
}

func deployStatusLabel(status domain.OperationStatus) string {
	return map[domain.OperationStatus]string{
		domain.StatusPending: "待下发", domain.StatusRunning: "下发中",
		domain.StatusSuccess: "已下发", domain.StatusFailed: "下发失败",
	}[status]
}

func certificateDeployError(cert *domain.Certificate) string {
	if cert == nil || cert.DeployStatus == domain.StatusRunning {
		return ""
	}
	var parts []string
	for _, agentID := range cert.TargetAgents {
		d := cert.Deploys[agentID]
		if d != nil && d.Status == domain.StatusFailed && strings.TrimSpace(d.Error) != "" {
			parts = append(parts, d.Error)
		}
	}
	return strings.Join(parts, "；")
}

// requestHTTPS marks the session cookie Secure when the browser connection is
// TLS, either directly or via a configured trusted proxy.
func (w *Web) requestHTTPS(r *http.Request) bool {
	return w.requestScheme(r) == "https"
}
