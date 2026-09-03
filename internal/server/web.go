package server

import (
	"context"
	"html/template"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

// Web is the HTTP handler for the Web UI. It renders Go templates with HTMX
// for interactivity and enforces a single-admin login.
type Web struct {
	srv      *Server
	tmpl     *template.Template
	sessions *sessionStore
	cookie   string
}

// NewWeb builds the Web handler, parsing the embedded templates.
func NewWeb(s *Server) (*Web, error) {
	tmpl, err := template.ParseFS(templatesFS, "web/templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Web{srv: s, tmpl: tmpl, sessions: newSessionStore(), cookie: "omc_session"}, nil
}

// Handler returns the route mux (with auth middleware and static assets).
func (w *Web) Handler() http.Handler {
	mux := http.NewServeMux()
	// Static assets. Register with a method so it is unambiguous against the
	// method-specific catch-all "GET /" (much more specific path wins).
	fileSrv := http.FileServer(http.FS(mustSub(staticFS, "web/static")))
	mux.Handle("GET /static/", http.StripPrefix("/static/", fileSrv))

	mux.HandleFunc("GET /login", w.handleLoginPage)
	mux.HandleFunc("POST /login", w.handleLoginPost)
	mux.HandleFunc("POST /logout", w.handleLogout)
	mux.HandleFunc("POST /setup", w.handleSetup)

	// Protected routes.
	mux.Handle("GET /", w.auth(w.handleDashboard))
	mux.Handle("GET /certificates", w.auth(w.handleCertificates))
	mux.Handle("GET /certificates/new", w.auth(w.handleCertificateNew))
	mux.Handle("POST /certificates", w.auth(w.handleCertificateCreate))
	mux.Handle("POST /certificates/{id}/issue", w.auth(w.handleIssue))
	mux.Handle("GET /certificates/{id}/row", w.auth(w.handleCertificateRow))
	mux.Handle("GET /certificates/{id}/log", w.auth(w.handleCertificateLog))
	mux.Handle("GET /certificates/{id}/log/content", w.auth(w.handleCertificateLogContent))
	mux.Handle("POST /certificates/{id}/deploy", w.auth(w.handleDeploy))

	mux.Handle("GET /credentials", w.auth(w.handleCredentials))
	mux.Handle("GET /credentials/new", w.auth(w.handleCredentialNew))
	mux.Handle("POST /credentials", w.auth(w.handleCredentialCreate))
	mux.Handle("GET /credentials/{id}/edit", w.auth(w.handleCredentialEdit))
	mux.Handle("POST /credentials/{id}", w.auth(w.handleCredentialUpdate))

	mux.Handle("GET /agents", w.auth(w.handleAgents))
	mux.Handle("POST /agents/token", w.auth(w.handleAgentToken))
	mux.Handle("POST /agents/{id}/update", w.auth(w.handleAgentUpdate))
	mux.Handle("POST /agents/{id}/delete", w.auth(w.handleAgentDelete))

	mux.Handle("GET /settings", w.auth(w.handleSettings))
	mux.Handle("POST /settings", w.auth(w.handleSettingsSave))
	mux.Handle("POST /settings/update", w.auth(w.handleServerUpdate))
	mux.Handle("POST /settings/ca", w.auth(w.handleCAAdd))
	mux.Handle("POST /settings/ca/{id}/default", w.auth(w.handleCADefault))

	return w.secure(mux)
}

// secure enforces auth except for static/login and sets hardening headers.
func (w *Web) secure(child http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("X-Frame-Options", "DENY")
		child.ServeHTTP(rw, r)
	})
}

// --- auth middleware ---

func (w *Web) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		id := requestSession(r)
		if !w.sessions.valid(id) {
			http.Redirect(rw, r, "/login", http.StatusFound)
			return
		}
		next(rw, r)
	})
}

func (w *Web) sessionCookieAndSet(rw http.ResponseWriter, id string) {
	http.SetCookie(rw, &http.Cookie{
		Name:     w.cookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   rw.Header().Get("X-Forwarded-Proto") == "https",
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
// (e.g. "dashboard") is executed into a buffer and inserted as .Content.
func (w *Web) page(rw http.ResponseWriter, r *http.Request, title, path, fragment string, data any) error {
	var b strings.Builder
	if err := w.tmpl.ExecuteTemplate(&b, fragment, data); err != nil {
		w.srv.log.Error("render page fragment failed", "fragment", fragment, "err", err)
		http.Error(rw, "页面渲染失败，请查看 Server 日志", http.StatusInternalServerError)
		return err
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := w.tmpl.ExecuteTemplate(rw, "layout", map[string]any{
		"Title": title, "Path": path, "Content": template.HTML(b.String()),
	}); err != nil {
		w.srv.log.Error("render page layout failed", "fragment", fragment, "err", err)
		return err
	}
	return nil
}

func (w *Web) redirect(rw http.ResponseWriter, r *http.Request, to string) {
	http.Redirect(rw, r, to, http.StatusFound)
}

// --- login / setup ---

func (w *Web) handleLoginPage(rw http.ResponseWriter, r *http.Request) {
	if w.srv.setupPending() {
		w.render(rw, r, "login", map[string]any{"Setup": true})
		return
	}
	w.render(rw, r, "login", map[string]any{})
}

func (w *Web) handleLoginPost(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	admin := w.srv.getAdmin()

	initialised := admin.SetupTokenUsed
	if !initialised {
		w.redirect(rw, r, "/login")
		return
	}
	if admin.Username == username && verifyPassword(password, admin.PasswordHash) {
		id := w.sessions.create(username)
		w.sessionCookieAndSet(rw, id)
		w.redirect(rw, r, "/")
		return
	}
	w.render(rw, r, "login", map[string]any{"Error": "用户名或密码错误"})
}

func (w *Web) handleSetup(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	admin := w.srv.getAdmin()
	invalid := admin.SetupTokenUsed || admin.SetupToken == "" ||
		time.Now().After(admin.SetupTokenExpiresAt) ||
		r.FormValue("setup_token") != admin.SetupToken
	if invalid {
		w.render(rw, r, "login", map[string]any{"Error": "初始化令牌无效或已过期，请重启 Server 生成新令牌", "Setup": true})
		return
	}
	if err := w.srv.setAdminPassword(r.FormValue("username"), r.FormValue("password")); err != nil {
		w.render(rw, r, "login", map[string]any{"Error": err.Error(), "Setup": true})
		return
	}
	w.redirect(rw, r, "/login")
}

func (w *Web) handleLogout(rw http.ResponseWriter, r *http.Request) {
	id := requestSession(r)
	w.sessions.delete(id)
	http.SetCookie(rw, &http.Cookie{Name: w.cookie, Value: "", Path: "/", MaxAge: -1})
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
	st := w.srv.st.State()
	creds := []map[string]any{}
	for _, c := range st.Credentials {
		creds = append(creds, map[string]any{"ID": c.ID, "Name": c.Name})
	}
	cas := []map[string]any{}
	for _, c := range st.CAs {
		isDefault := c.ID == st.Config.DefaultACMEID
		cas = append(cas, map[string]any{"ID": c.ID, "Name": c.Name, "Default": isDefault})
	}
	agents := []map[string]any{}
	for _, a := range st.Agents {
		agents = append(agents, map[string]any{"ID": a.ID, "Name": a.Name, "Address": a.Address})
	}
	w.page(rw, r, "新建证书", "/certificates", "certnew", map[string]any{
		"Credentials": creds, "CAs": cas, "Agents": agents,
	})
}

func (w *Web) handleCertificateCreate(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	agents := r.Form["agents"]
	if _, err := w.srv.CreateCertificate(
		r.FormValue("root"), r.FormValue("credential_id"), r.FormValue("acme_id"),
		domain.KeyType(r.FormValue("key_type")), agents,
	); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	w.redirect(rw, r, "/certificates")
}

func (w *Web) handleIssue(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, _, err := w.srv.StartIssue(id, taskTypeIssue); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
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
	return map[string]any{
		"ID": id, "RootDomain": cert.RootDomain, "Log": logText,
		"Running": cert.IssueStatus == domain.StatusRunning,
	}, true
}

func (w *Web) handleDeploy(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := w.srv.DeployAll(r.Context(), id); err != nil {
		writeJSONErr(rw, http.StatusBadGateway, err.Error())
		return
	}
	w.renderCertificateRow(rw, id)
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
		r.FormValue("name"), r.FormValue("token"), r.FormValue("zone_id"),
		r.FormValue("account_id"), r.FormValue("remark"),
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
	enabled := r.FormValue("enabled") == "on"
	err := w.srv.UpdateCredential(id, r.FormValue("name"), r.FormValue("token"),
		r.FormValue("zone_id"), r.FormValue("account_id"), r.FormValue("remark"), enabled)
	if err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	w.redirect(rw, r, "/credentials")
}

// --- agents ---

func (w *Web) handleAgents(rw http.ResponseWriter, r *http.Request) {
	type row struct {
		ID, Name, Addr, Status, StatusLabel, Version, Platform, CertExpiresAt string
		UpdateStatus, UpdateTarget, UpdateError, UpdateHint                   string
		Versions                                                              []string
		DefaultVersion                                                        string
	}
	initial := w.srv.st.State()
	rows := make([]row, 0, len(initial.Agents))
	for agentID := range initial.Agents {
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		versions, versionErr := w.srv.AgentVersions(ctx, agentID)
		cancel()
		a := w.srv.st.State().Agents[agentID]
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
		defaultVersion := ""
		if containsString(versions, Version) {
			defaultVersion = Version
		} else if len(versions) > 0 {
			defaultVersion = versions[0]
		}
		hint := ""
		if versionErr != nil {
			hint = versionErr.Error()
		}
		platform := "—"
		if a.GOOS != "" && a.GOARCH != "" {
			platform = a.GOOS + "/" + a.GOARCH
		}
		rows = append(rows, row{
			ID: a.ID, Name: a.Name, Addr: a.Address + ":" + strconv.Itoa(a.Port),
			Status: string(a.Status), StatusLabel: statusLabel, Version: a.Version,
			Platform: platform, CertExpiresAt: expiresAt,
			UpdateStatus: string(a.UpdateStatus), UpdateTarget: a.UpdateTargetVersion,
			UpdateError: a.UpdateError, UpdateHint: hint,
			Versions: versions, DefaultVersion: defaultVersion,
		})
	}
	w.page(rw, r, "Agent", "/agents", "agents", map[string]any{"Agents": rows, "ServerVersion": Version})
}

func (w *Web) handleAgentToken(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.FormValue("name")
	token, agentID, err := w.srv.CreateAgentToken(name)
	if err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	_ = agentID
	cmd := w.srv.AgentInstallCommand(name, token)
	w.page(rw, r, "Agent", "/agents", "agents", map[string]any{"InstallCommand": cmd, "ServerVersion": Version})
}

func (w *Web) handleAgentUpdate(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	if err := w.srv.StartAgentUpdate(r.PathValue("id"), r.FormValue("version")); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	w.redirect(rw, r, "/agents")
}

func (w *Web) handleAgentDelete(rw http.ResponseWriter, r *http.Request) {
	w.srv.DeleteAgent(r.PathValue("id"))
	w.redirect(rw, r, "/agents")
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
	w.page(rw, r, "设置", "/settings", "settings", map[string]any{
		"CAs": cas, "Email": st.Config.ACMEAccountEmail,
		"RenewDays": st.Config.RenewPreferenceDays, "DNSSleep": st.Config.DNSSleepSeconds,
		"ServerVersion": Version, "ServerVersions": versions, "UpdateHint": updateHint,
		"UpdateStatus": string(update.Status), "UpdateTarget": update.Target, "UpdateError": update.Error,
	})
}

func (w *Web) handleServerUpdate(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	if err := w.srv.StartSelfUpdate(r.FormValue("version")); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	w.redirect(rw, r, "/settings")
}

func (w *Web) handleSettingsSave(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	renewDays, _ := strconv.Atoi(r.FormValue("renew_days"))
	dnsSleep, _ := strconv.Atoi(r.FormValue("dns_sleep"))
	_ = w.srv.st.WithState(true, func(st *domain.State) error {
		st.Config.ACMEAccountEmail = strings.TrimSpace(r.FormValue("email"))
		if renewDays > 0 {
			st.Config.RenewPreferenceDays = renewDays
		}
		st.Config.DNSSleepSeconds = dnsSleep
		return nil
	})
	w.redirect(rw, r, "/settings")
}

func (w *Web) handleCAAdd(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	id, _ := newID()
	_ = w.srv.st.WithState(true, func(st *domain.State) error {
		st.CAs[id] = &domain.ACMECA{
			ID: id, Name: r.FormValue("name"), DirectoryURL: r.FormValue("directory_url"),
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
	ID               string
	RootDomain       string
	IssueStatus      string
	IssueStatusLabel string
	ExpiresAt        string
	KeyType          string
	LastError        string
	Running          bool
	CanDeploy        bool
}

func makeCertificateRow(cert *domain.Certificate) certificateRow {
	label := map[domain.OperationStatus]string{
		domain.StatusPending: "待签发", domain.StatusRunning: "签发中",
		domain.StatusSuccess: "已签发", domain.StatusFailed: "失败",
	}[cert.IssueStatus]
	expiresAt := "—"
	if cert.Current != nil {
		expiresAt = cert.Current.ExpiresAt.Format("2006-01-02")
	}
	return certificateRow{
		ID: cert.ID, RootDomain: cert.RootDomain,
		IssueStatus: string(cert.IssueStatus), IssueStatusLabel: label,
		ExpiresAt: expiresAt, KeyType: string(cert.KeyType), LastError: cert.LastError,
		Running: cert.IssueStatus == domain.StatusRunning, CanDeploy: cert.Current != nil,
	}
}
