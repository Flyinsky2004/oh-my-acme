package server

import (
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
	mux.Handle("POST /certificates/{id}/deploy", w.auth(w.handleDeploy))

	mux.Handle("GET /credentials", w.auth(w.handleCredentials))
	mux.Handle("GET /credentials/new", w.auth(w.handleCredentialNew))
	mux.Handle("POST /credentials", w.auth(w.handleCredentialCreate))
	mux.Handle("GET /credentials/{id}/edit", w.auth(w.handleCredentialEdit))
	mux.Handle("POST /credentials/{id}", w.auth(w.handleCredentialUpdate))

	mux.Handle("GET /agents", w.auth(w.handleAgents))
	mux.Handle("POST /agents/token", w.auth(w.handleAgentToken))
	mux.Handle("POST /agents/{id}/delete", w.auth(w.handleAgentDelete))

	mux.Handle("GET /settings", w.auth(w.handleSettings))
	mux.Handle("POST /settings", w.auth(w.handleSettingsSave))
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
		return err
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	return w.tmpl.ExecuteTemplate(rw, "layout", map[string]any{
		"Title": title, "Path": path, "Content": template.HTML(b.String()),
	})
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
	type row struct {
		ID, RootDomain, IssueStatus, IssueStatusLabel, ExpiresAt, KeyType, LastError string
	}
	rows := []row{}
	for _, c := range st.Certificates {
		label := map[domain.OperationStatus]string{
			domain.StatusPending: "待签发", domain.StatusRunning: "签发中",
			domain.StatusSuccess: "已签发", domain.StatusFailed: "失败",
		}[c.IssueStatus]
		exp := "—"
		if c.Current != nil {
			exp = c.Current.ExpiresAt.Format("2006-01-02")
		}
		rows = append(rows, row{
			ID: c.ID, RootDomain: c.RootDomain, IssueStatus: string(c.IssueStatus),
			IssueStatusLabel: label, ExpiresAt: exp, KeyType: string(c.KeyType), LastError: c.LastError,
		})
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
	if err := w.srv.Issue(r.Context(), id); err != nil {
		writeJSONErr(rw, http.StatusBadRequest, err.Error())
		return
	}
	// Return the updated cert row.
	cert := w.srv.st.State().Certificates[id]
	writeCertRow(rw, cert)
}

func (w *Web) handleDeploy(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := w.srv.DeployAll(r.Context(), id); err != nil {
		writeJSONErr(rw, http.StatusBadGateway, err.Error())
		return
	}
	cert := w.srv.st.State().Certificates[id]
	writeCertRow(rw, cert)
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
	st := w.srv.st.State()
	type row struct {
		ID, Name, Addr, Status, StatusLabel, Version, CertExpiresAt string
	}
	rows := []row{}
	for _, a := range st.Agents {
		label := map[domain.AgentStatus]string{
			domain.AgentRegistered: "在线", domain.AgentUnreachable: "不可达",
			domain.AgentDisabled: "已禁用", domain.AgentUnregistered: "未注册",
		}[a.Status]
		exp := "—"
		if !a.CertExpiresAt.IsZero() {
			exp = a.CertExpiresAt.Format("2006-01-02")
		}
		rows = append(rows, row{a.ID, a.Name, a.Address + ":" + strconv.Itoa(a.Port),
			string(a.Status), label, a.Version, exp})
	}
	w.page(rw, r, "Agent", "/agents", "agents", map[string]any{"Agents": rows})
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
	w.page(rw, r, "Agent", "/agents", "agents", map[string]any{"InstallCommand": cmd})
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
	w.page(rw, r, "设置", "/settings", "settings", map[string]any{
		"CAs": cas, "Email": st.Config.ACMEAccountEmail,
		"RenewDays": st.Config.RenewPreferenceDays, "DNSSleep": st.Config.DNSSleepSeconds,
	})
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

func writeCertRow(rw http.ResponseWriter, cert *domain.Certificate) {
	label := map[domain.OperationStatus]string{
		domain.StatusPending: "待签发", domain.StatusRunning: "签发中",
		domain.StatusSuccess: "已签发", domain.StatusFailed: "失败",
	}[cert.IssueStatus]
	exp := "—"
	if cert.Current != nil {
		exp = cert.Current.ExpiresAt.Format("2006-01-02")
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Rendered inline; a dedicated template keeps the partial self-contained.
	var sb strings.Builder
	tmplHTML(&sb, `<tr id="cert-`+cert.ID+`"><td><strong>`+template.HTMLEscapeString(cert.RootDomain)+`</strong></td><td><span class="badge `+string(cert.IssueStatus)+`">`+label+`</span>`+spanErr(cert.LastError)+`</td><td>`+exp+`</td><td>`+string(cert.KeyType)+`</td><td><button hx-post="/certificates/`+cert.ID+`/issue" hx-target="#cert-`+cert.ID+`" hx-swap="outerHTML">签发</button> <button hx-post="/certificates/`+cert.ID+`/deploy" hx-target="#cert-`+cert.ID+`" hx-swap="outerHTML">下发</button></td></tr>`)
	_, _ = rw.Write([]byte(sb.String()))
}

func spanErr(err string) string {
	if err == "" {
		return ""
	}
	return `<span class="tooltip" title="` + template.HTMLEscapeString(err) + `">!</span>`
}

func tmplHTML(w *strings.Builder, s string) { w.WriteString(s) }
