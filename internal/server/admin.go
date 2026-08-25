package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"proxy/internal/auth"
	"proxy/internal/certs"
	"proxy/internal/config"
	"proxy/internal/metrics"
	"proxy/internal/rules"
	"proxy/internal/security"
	"proxy/internal/store"
)

const secretMask = "***SET***"

var hostRE = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

type Admin struct {
	store   *config.Store
	engine  *rules.Engine
	auth    *auth.Authenticator
	certs   *certs.Manager
	webFS   fs.FS
	logger  *log.Logger
	audit   *security.AuditLog
	limIP   *security.Limiter
	limUser *security.Limiter
	limTOTP *security.Limiter
	started time.Time

	healthDetail func() map[string]any
	metrics      *metrics.Metrics

	bdBackup  func() (any, error)
	bdList    func() []store.BackupInfo
	bdRestore func(string) (map[string]int, error)
	bdDelete  func(string) error
}

type storageReq struct {
	File string `json:"file"`
}

func New(store *config.Store, engine *rules.Engine, authn *auth.Authenticator, cm *certs.Manager, webFS fs.FS, logger *log.Logger, audit *security.AuditLog, limIP, limUser, limTOTP *security.Limiter) *Admin {
	return &Admin{
		store:   store,
		engine:  engine,
		auth:    authn,
		certs:   cm,
		webFS:   webFS,
		logger:  logger,
		audit:   audit,
		limIP:   limIP,
		limUser: limUser,
		limTOTP: limTOTP,
		started: time.Now(),
	}
}

func (a *Admin) SetHealthDetail(fn func() map[string]any) { a.healthDetail = fn }

func (a *Admin) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if a.metrics == nil {
		http.Error(w, "metrics no disponibles", http.StatusServiceUnavailable)
		return
	}
	a.metrics.Handler().ServeHTTP(w, r)
}

func (a *Admin) SetMetrics(m *metrics.Metrics) { a.metrics = m }

func (a *Admin) SetStorageOps(backup func() (any, error), list func() []store.BackupInfo, restore func(string) (map[string]int, error), delete func(string) error) {
	a.bdBackup = backup
	a.bdList = list
	a.bdRestore = restore
	a.bdDelete = delete
}

func (a *Admin) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", a.handleLoginPage)
	mux.HandleFunc("POST /auth/login/ldap", a.handleLDAPLogin)
	mux.HandleFunc("POST /auth/login/local", a.handleLocalLogin)
	mux.HandleFunc("GET /auth/callback", a.auth.HandleCallback)
	mux.HandleFunc("GET /auth/logout", a.auth.HandleLogout)
	mux.HandleFunc("GET /auth/2fa", a.handle2FAPage)
	mux.HandleFunc("POST /auth/2fa/verify", a.handle2FAVerify)
	mux.HandleFunc("GET /auth/2fa/enroll", a.handle2FAEnrollPage)
	mux.HandleFunc("POST /auth/2fa/enroll/confirm", a.handle2FAEnrollConfirm)
	mux.HandleFunc("GET /{$}", a.requirePage(a.handleIndex))
	mux.HandleFunc("GET /style.css", a.requirePage(a.serveAsset("style.css")))
	mux.HandleFunc("GET /app.js", a.requirePage(a.serveAsset("app.js")))
	mux.HandleFunc("GET /favicon.svg", a.serveAsset("favicon.svg"))
	mux.HandleFunc("GET /metrics", a.metricsHandler)
	mux.HandleFunc("GET /api/session", a.handleSession)
	mux.HandleFunc("GET /api/upstream-health", a.requireAPI(a.handleUpstreamHealth))
	mux.HandleFunc("GET /api/load-balancing", a.requireAPI(a.handleLoadBalancing))
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{"ok": true, "uptime_seconds": int(time.Since(a.started).Seconds())}
		if a.healthDetail != nil {
			for k, v := range a.healthDetail() {
				body[k] = v
			}
		}
		writeJSON(w, http.StatusOK, body)
	})
	mux.HandleFunc("GET /api/rules", a.requireAPI(a.handleRulesGet))
	mux.HandleFunc("POST /api/rules", a.requireAPI(a.handleRulesPost))
	mux.HandleFunc("POST /api/rules/delete", a.requireAPI(a.handleRulesDelete))
	mux.HandleFunc("GET /api/config", a.requireAPI(a.handleConfigGet))
	mux.HandleFunc("POST /api/config", a.requireAPI(a.handleConfigPost))
	mux.HandleFunc("GET /api/storage/backups", a.requireAPI(func(w http.ResponseWriter, r *http.Request) {
		if a.bdList == nil {
			jsonErr(w, http.StatusBadRequest, "los backups de BD requieren storage.backend=postgres")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"backups": a.bdList()})
	}))
	mux.HandleFunc("POST /api/storage/backup", a.requireAPI(func(w http.ResponseWriter, r *http.Request) {
		if a.bdBackup == nil {
			jsonErr(w, http.StatusBadRequest, "los backups de BD requieren storage.backend=postgres")
			return
		}
		res, err := a.bdBackup()
		if err != nil {
			a.audit.Log("bd_backup_error", security.ClientIP(r), "", err.Error())
			jsonErr(w, http.StatusInternalServerError, "no se pudo crear el backup: "+err.Error())
			return
		}
		a.audit.Log("bd_backup", security.ClientIP(r), "", "")
		writeJSON(w, http.StatusOK, res)
	}))
	mux.HandleFunc("POST /api/storage/restore", a.requireAPI(func(w http.ResponseWriter, r *http.Request) {
		if a.bdRestore == nil {
			jsonErr(w, http.StatusBadRequest, "el restore requiere storage.backend=postgres")
			return
		}
		var req storageReq
		if err := decodeJSON(r, &req); err != nil {
			writeDecodeErr(w, err)
			return
		}
		done, err := a.bdRestore(req.File)
		if err != nil {
			a.audit.Log("bd_restore_error", security.ClientIP(r), "", err.Error())
			jsonErr(w, http.StatusInternalServerError, "restore fallido: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restored": done})
	}))
	mux.HandleFunc("POST /api/storage/delete", a.requireAPI(func(w http.ResponseWriter, r *http.Request) {
		if a.bdDelete == nil {
			jsonErr(w, http.StatusBadRequest, "la eliminacion requiere storage.backend=postgres")
			return
		}
		var req storageReq
		if err := decodeJSON(r, &req); err != nil {
			writeDecodeErr(w, err)
			return
		}
		if err := a.bdDelete(req.File); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.audit.Log("bd_backup_deleted", security.ClientIP(r), "", req.File)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))
	mux.HandleFunc("POST /api/setup", a.handleSetup)
	mux.HandleFunc("POST /api/ldap-test", a.requireAPI(a.handleLDAPTest))
	mux.HandleFunc("POST /api/local-password", a.requireAPI(a.handleLocalPassword))
	mux.HandleFunc("POST /api/sessions/revoke", a.requireAPI(a.handleRevokeSessions))
	mux.HandleFunc("GET /api/security", a.requireAPI(a.handleSecurityInfo))
	mux.HandleFunc("GET /api/totp", a.requireAPI(a.handleTOTPGet))
	mux.HandleFunc("POST /api/totp/settings", a.requireAPI(a.handleTOTPSettings))
	mux.HandleFunc("POST /api/totp/reset", a.requireAPI(a.handleTOTPReset))
	mux.HandleFunc("GET /api/certs", a.requireAPI(a.handleCertsGet))
	mux.HandleFunc("GET /api/certs/status", a.requireAPI(a.handleCertsStatus))
	mux.HandleFunc("POST /api/certs/acme", a.requireAPI(a.handleCertACMESet))
	mux.HandleFunc("POST /api/certs/custom", a.requireAPI(a.handleCertCustomPut))
	mux.HandleFunc("POST /api/certs/custom/delete", a.requireAPI(a.handleCertCustomDelete))
	mux.HandleFunc("POST /api/certs/renew", a.requireAPI(a.handleCertRenew))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return security.Chain(mux,
		security.Recover(a.logger),
		security.SecureHeaders(true),
		security.BodyLimit(1<<20),
		security.CheckOrigin(),
		a.ipAllowlistMW(),
	)
}

func (a *Admin) ipAllowlistMW() security.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cidrs := a.store.Get().AdminAllowedCIDRs
			if len(cidrs) > 0 {
				nets, _ := security.ParseCIDRList(cidrs)
				if !security.IPInNets(security.ClientIP(r), nets) {
					a.audit.Log("admin_blocked_ip", security.ClientIP(r), "", "no esta en la lista blanca")
					http.Error(w, "403: acceso no autorizado", http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *Admin) isPanelAdmin(u *auth.UserClaims, cfg config.Config) bool {
	if len(cfg.PanelAdmins) == 0 {
		return true
	}
	if u == nil {
		return false
	}
	for _, cand := range auth.IdentityCandidates(u) {
		for _, adm := range cfg.PanelAdmins {
			if strings.EqualFold(strings.TrimSpace(adm), cand) {
				return true
			}
		}
	}
	return false
}

func (a *Admin) requirePage(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := a.auth.SessionFromRequest(r)
		if err != nil {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		if !a.isPanelAdmin(u, a.store.Get()) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Acceso denegado</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"></head><body style="font-family:sans-serif;text-align:center;padding:3rem"><h1>403</h1><p>Esta cuenta no tiene rol de administrador del panel.</p></body></html>`))
			return
		}
		next(w, r)
	}
}

func (a *Admin) requireAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := a.auth.SessionFromRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "sesion requerida"})
			return
		}
		if !a.isPanelAdmin(u, a.store.Get()) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "requiere rol de administrador del panel"})
			return
		}
		r.Header.Set("X-Px-User", u.Email)
		next(w, r)
	}
}

func (a *Admin) serveAsset(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFileFS(w, r, a.webFS, name)
	}
}

func (a *Admin) handleIndex(w http.ResponseWriter, r *http.Request) {
	a.serveAsset("index.html")(w, r)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type bodyTooLargeError struct{ err *http.MaxBytesError }

func (e bodyTooLargeError) Error() string { return e.err.Error() }

func writeDecodeErr(w http.ResponseWriter, err error) {
	var bte bodyTooLargeError
	if errors.As(err, &bte) {
		jsonErr(w, http.StatusRequestEntityTooLarge, "cuerpo demasiado grande")
		return
	}
	jsonErr(w, http.StatusBadRequest, "json invalido")
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return bodyTooLargeError{err: mbe}
		}
		return err
	}
	return nil
}

func isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func pickSecret(current, incoming string) string {
	incoming = strings.TrimSpace(incoming)
	if incoming == "" || incoming == secretMask {
		return current
	}
	return incoming
}

func pickString(current, incoming string) string {
	incoming = strings.TrimSpace(incoming)
	if incoming == "" {
		return current
	}
	return incoming
}

type sessionResp struct {
	Authenticated   bool             `json:"authenticated"`
	User            *auth.UserClaims `json:"user,omitempty"`
	SetupRequired   bool             `json:"setup_required"`
	EntraEnabled    bool             `json:"entra_enabled"`
	LdapEnabled     bool             `json:"ldap_enabled"`
	LocalEnabled    bool             `json:"local_enabled"`
	DefaultPassword bool             `json:"default_password"`
	IsAdmin         bool             `json:"is_admin"`
}

func (a *Admin) handleSession(w http.ResponseWriter, r *http.Request) {
	u, err := a.auth.SessionFromRequest(r)
	cfg := a.store.Get()
	defaultPw := false
	if err == nil {
		defaultPw = cfg.LocalAdmin.IsDefaultPassword()
	}
	resp := sessionResp{
		Authenticated:   err == nil,
		User:            u,
		SetupRequired:   !a.auth.EntraEnabled() && !cfg.LDAP.Enabled,
		EntraEnabled:    a.auth.EntraEnabled(),
		LdapEnabled:     cfg.LDAP.Enabled,
		LocalEnabled:    cfg.LocalAdmin.Enabled,
		DefaultPassword: defaultPw,
		IsAdmin:         err == nil && a.isPanelAdmin(u, cfg),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *Admin) handleRulesGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": a.store.Get().Rules})
}

func (a *Admin) rebuild() {
	a.engine.Rebuild(a.store.Get().Rules)
}

func (a *Admin) handleRulesPost(w http.ResponseWriter, r *http.Request) {
	var rule config.Rule
	if err := decodeJSON(r, &rule); err != nil {
		writeDecodeErr(w, err)
		return
	}
	rule.Host = rules.NormalizeHost(rule.Host)
	if rule.Host != "localhost" && !hostRE.MatchString(rule.Host) {
		jsonErr(w, http.StatusBadRequest, "dominio invalido (ejemplo: app.midominio.local o *.midominio.local)")
		return
	}
	if len(rule.Targets) > 0 {
		validLB := map[string]bool{"round-robin": true, "weighted": true, "least-connections": true}
		if rule.LoadBalancing != "" && !validLB[rule.LoadBalancing] {
			jsonErr(w, http.StatusBadRequest, "load_balancing invalido: round-robin, weighted, least-connections")
			return
		}
		for i, bt := range rule.Targets {
			t, err := url.Parse(strings.TrimSpace(bt.URL))
			if err != nil || (t.Scheme != "http" && t.Scheme != "https") || t.Host == "" {
				jsonErr(w, http.StatusBadRequest, fmt.Sprintf("backend %d: destino invalido", i+1))
				return
			}
			rule.Targets[i].URL = strings.TrimSpace(bt.URL)
		}
	} else {
		tgt, err := url.Parse(strings.TrimSpace(rule.Target))
		if err != nil || (tgt.Scheme != "http" && tgt.Scheme != "https") || tgt.Host == "" {
			jsonErr(w, http.StatusBadRequest, "destino invalido, debe ser una URL http(s)")
			return
		}
	}
	err := a.store.Update(func(c *config.Config) {
		found := false
		for i := range c.Rules {
			if rules.NormalizeHost(c.Rules[i].Host) == rule.Host {
				c.Rules[i] = rule
				found = true
				break
			}
		}
		if !found {
			c.Rules = append(c.Rules, rule)
		}
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "no se pudo guardar")
		return
	}
	a.rebuild()
	a.audit.Log("rule_upsert", security.ClientIP(r), r.Header.Get("X-Px-User"), rule.Host+" -> "+rule.Target)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rules": a.store.Get().Rules})
}

func (a *Admin) handleRulesDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeErr(w, err)
		return
	}
	target := rules.NormalizeHost(body.Host)
	err := a.store.Update(func(c *config.Config) {
		out := c.Rules[:0]
		for _, rl := range c.Rules {
			if rules.NormalizeHost(rl.Host) != target {
				out = append(out, rl)
			}
		}
		c.Rules = out
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "no se pudo guardar")
		return
	}
	a.rebuild()
	a.audit.Log("rule_delete", security.ClientIP(r), r.Header.Get("X-Px-User"), target)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rules": a.store.Get().Rules})
}

func (a *Admin) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Get()
	if cfg.Azure.ClientSecret != "" {
		cfg.Azure.ClientSecret = secretMask
	}
	if cfg.SessionSecret != "" {
		cfg.SessionSecret = secretMask
	}
	if cfg.LocalAdmin.PasswordHash != "" {
		cfg.LocalAdmin.PasswordHash = secretMask
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (a *Admin) handleConfigPost(w http.ResponseWriter, r *http.Request) {
	var req config.Config
	if err := decodeJSON(r, &req); err != nil {
		writeDecodeErr(w, err)
		return
	}
	err := a.store.Update(func(c *config.Config) {
		if req.AdminPort > 0 && req.AdminPort < 65536 {
			c.AdminPort = req.AdminPort
		}
		if req.ProxyHTTPPort > 0 && req.ProxyHTTPPort < 65536 {
			c.ProxyHTTPPort = req.ProxyHTTPPort
		}
		if req.ProxyHTTPSPort > 0 && req.ProxyHTTPSPort < 65536 {
			c.ProxyHTTPSPort = req.ProxyHTTPSPort
		}
		c.TLSCertFile = pickString(c.TLSCertFile, req.TLSCertFile)
		c.TLSKeyFile = pickString(c.TLSKeyFile, req.TLSKeyFile)
		c.PanelTLSCertFile = pickString(c.PanelTLSCertFile, req.PanelTLSCertFile)
		c.PanelTLSKeyFile = pickString(c.PanelTLSKeyFile, req.PanelTLSKeyFile)
		if req.SessionHours >= 1 && req.SessionHours <= 720 {
			c.SessionHours = req.SessionHours
		}
		c.InsecureUpstream = req.InsecureUpstream
		c.Azure.TenantID = strings.TrimSpace(req.Azure.TenantID)
		c.Azure.ClientID = strings.TrimSpace(req.Azure.ClientID)
		c.Azure.ClientSecret = pickSecret(c.Azure.ClientSecret, req.Azure.ClientSecret)
		c.Azure.RedirectURL = strings.TrimSpace(req.Azure.RedirectURL)
		c.Azure.AllowedEmails = cleanList(req.Azure.AllowedEmails)
		c.Azure.AllowedGroups = cleanList(req.Azure.AllowedGroups)
		c.LDAP.Enabled = req.LDAP.Enabled
		c.LDAP.URL = strings.TrimSpace(req.LDAP.URL)
		c.LDAP.InsecureTLS = req.LDAP.InsecureTLS
		c.LDAP.BaseDN = strings.TrimSpace(req.LDAP.BaseDN)
		c.LDAP.BindUPNSuffix = strings.TrimSpace(req.LDAP.BindUPNSuffix)
		if strings.TrimSpace(req.LDAP.UserFilter) != "" {
			c.LDAP.UserFilter = strings.TrimSpace(req.LDAP.UserFilter)
		}
		c.LDAP.AllowedEmails = cleanList(req.LDAP.AllowedEmails)
		c.LDAP.AllowedGroups = cleanList(req.LDAP.AllowedGroups)
		c.LocalAdmin.Enabled = req.LocalAdmin.Enabled
		if s := strings.TrimSpace(req.LocalAdmin.Username); s != "" {
			c.LocalAdmin.Username = s
		}
		c.LocalAdmin.PasswordHash = pickSecret(c.LocalAdmin.PasswordHash, req.LocalAdmin.PasswordHash)
		c.SessionSecret = pickSecret(c.SessionSecret, req.SessionSecret)
		c.SecureCookies = req.SecureCookies
		if cidrs := cleanList(req.AdminAllowedCIDRs); len(cidrs) > 0 {
			c.AdminAllowedCIDRs = cidrs
		}
		if pa := cleanList(req.PanelAdmins); len(pa) > 0 {
			c.PanelAdmins = pa
		}
		if req.LoginMaxFails > 0 && req.LoginMaxFails <= 100 {
			c.LoginMaxFails = req.LoginMaxFails
		}
		if req.LockoutMinutes > 0 && req.LockoutMinutes <= 1440 {
			c.LockoutMinutes = req.LockoutMinutes
		}
		c.ACME.Enabled = req.ACME.Enabled
		c.ACME.Domains = cleanList(req.ACME.Domains)
		if s := strings.TrimSpace(req.ACME.CacheDir); s != "" {
			c.ACME.CacheDir = s
		}
		c.ACME.RedirectHTTP = req.ACME.RedirectHTTP
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "no se pudo guardar")
		return
	}
	var warning string
	if werr := a.auth.Reload(); werr != nil {
		warning = werr.Error()
	}
	a.rebuild()
	a.audit.Log("config_update", security.ClientIP(r), r.Header.Get("X-Px-User"), warning)
	cfg := a.store.Get()
	if cfg.Azure.ClientSecret != "" {
		cfg.Azure.ClientSecret = secretMask
	}
	if cfg.SessionSecret != "" {
		cfg.SessionSecret = secretMask
	}
	if cfg.LocalAdmin.PasswordHash != "" {
		cfg.LocalAdmin.PasswordHash = secretMask
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "warning": warning, "config": cfg})
}

type setupReq struct {
	TenantID      string   `json:"tenant_id"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	RedirectURL   string   `json:"redirect_url"`
	AllowedEmails []string `json:"allowed_emails"`
	AllowedGroups []string `json:"allowed_groups"`
	EnableLDAP    bool     `json:"enable_ldap"`
	LDAP          *struct {
		URL           string   `json:"url"`
		BaseDN        string   `json:"base_dn"`
		BindUPNSuffix string   `json:"bind_upn_suffix"`
		UserFilter    string   `json:"user_filter"`
		InsecureTLS   bool     `json:"insecure_tls"`
		AllowedGroups []string `json:"allowed_groups"`
	} `json:"ldap"`
}

func (a *Admin) handleSetup(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Get()
	_, sessErr := a.auth.SessionFromRequest(r)
	anyEnabled := a.auth.EntraEnabled() || cfg.LDAP.Enabled || cfg.LocalAdmin.Enabled
	if sessErr != nil && !(isLoopback(r) && !anyEnabled) {
		jsonErr(w, http.StatusForbidden, "requiere una sesion iniciada")
		return
	}
	var req setupReq
	if err := decodeJSON(r, &req); err != nil {
		writeDecodeErr(w, err)
		return
	}
	if req.EnableLDAP && req.LDAP == nil {
		jsonErr(w, http.StatusBadRequest, "faltan los datos del servidor LDAP")
		return
	}
	err := a.store.Update(func(c *config.Config) {
		c.Azure.TenantID = strings.TrimSpace(req.TenantID)
		c.Azure.ClientID = strings.TrimSpace(req.ClientID)
		c.Azure.ClientSecret = strings.TrimSpace(req.ClientSecret)
		if s := strings.TrimSpace(req.RedirectURL); s != "" {
			c.Azure.RedirectURL = s
		}
		c.Azure.AllowedEmails = cleanList(req.AllowedEmails)
		c.Azure.AllowedGroups = cleanList(req.AllowedGroups)
		if req.EnableLDAP && req.LDAP != nil {
			c.LDAP.Enabled = true
			c.LDAP.URL = strings.TrimSpace(req.LDAP.URL)
			c.LDAP.BaseDN = strings.TrimSpace(req.LDAP.BaseDN)
			c.LDAP.BindUPNSuffix = strings.TrimSpace(req.LDAP.BindUPNSuffix)
			if s := strings.TrimSpace(req.LDAP.UserFilter); s != "" {
				c.LDAP.UserFilter = s
			}
			c.LDAP.InsecureTLS = req.LDAP.InsecureTLS
			c.LDAP.AllowedGroups = cleanList(req.LDAP.AllowedGroups)
		}
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "no se pudo guardar")
		return
	}
	var warning string
	if werr := a.auth.Reload(); werr != nil {
		warning = werr.Error()
	}
	a.audit.Log("setup_completed", security.ClientIP(r), "", warning)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "warning": warning})
}

func (a *Admin) handleUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"upstreams": a.engine.TargetHealth()})
}

func (a *Admin) handleLoadBalancing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"load_balancing": a.engine.LoadBalancingInfo()})
}

func (a *Admin) handleLDAPTest(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Get()
	if !cfg.LDAP.Enabled {
		jsonErr(w, http.StatusBadRequest, "ldap no esta habilitado")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeErr(w, err)
		return
	}
	u, err := auth.LDAPLogin(cfg.LDAP, body.Username, body.Password)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": map[string]string{"email": u.Email, "name": u.Name}})
}

const loginPageHead = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Iniciar sesion | PxProxy</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:grid;place-items:center;font-family:"Segoe UI Variable","Segoe UI",system-ui,sans-serif;background:#070b16;color:#fff;overflow:hidden;padding:20px}
.blob{position:fixed;border-radius:50%;filter:blur(110px);opacity:.45;pointer-events:none;animation:drift 22s ease-in-out infinite alternate}
.b1{width:520px;height:520px;background:#3b5bfd;top:-160px;left:-120px}
.b2{width:460px;height:460px;background:#8a5cf6;bottom:-180px;right:-120px;animation-delay:-8s}
.b3{width:340px;height:340px;background:#0ea5a4;top:55%;left:58%;animation-delay:-15s;opacity:.28}
@keyframes drift{from{transform:translate(0,0) scale(1)}to{transform:translate(60px,-50px) scale(1.15)}}
.card{position:relative;width:min(430px,100%);padding:44px 38px 34px;border-radius:22px;background:rgba(15,21,38,.72);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);border:1px solid rgba(255,255,255,.09);box-shadow:0 30px 80px rgba(0,0,0,.55);animation:rise .5s ease-out}
@keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
.mark{display:inline-flex;width:52px;height:52px;border-radius:15px;align-items:center;justify-content:center;font-size:26px;color:#fff;background:linear-gradient(135deg,#4f7cff,#8a5cf6);box-shadow:0 10px 26px rgba(79,124,255,.4)}
h1{font-size:24px;margin-top:16px;letter-spacing:.2px}
.sub{color:rgba(255,255,255,.45);font-size:13.5px;margin-top:4px}
.alert{display:flex;gap:9px;align-items:flex-start;background:rgba(248,81,73,.13);border:1px solid rgba(248,81,73,.45);border-radius:11px;padding:11px 13px;font-size:13px;color:#ffb3ad;margin:18px 0 2px}
.alert svg{flex-shrink:0;margin-top:1px}
.ms-btn{display:flex;align-items:center;justify-content:center;gap:11px;width:100%;margin-top:22px;padding:12px;background:#fff;color:#1b1b1b;border:none;border-radius:12px;font-size:14px;font-weight:600;text-decoration:none;cursor:pointer;transition:transform .15s,box-shadow .15s}
.ms-btn:hover{transform:translateY(-1px);box-shadow:0 12px 28px rgba(255,255,255,.18)}
.divider{display:flex;align-items:center;gap:12px;color:rgba(255,255,255,.35);font-size:11px;text-transform:uppercase;letter-spacing:.12em;margin:20px 0}
.divider::before,.divider::after{content:"";flex:1;height:1px;background:rgba(255,255,255,.1)}
.tabs{display:flex;background:rgba(255,255,255,.06);border-radius:12px;padding:4px;margin-bottom:18px}
.tab-btn{flex:1;padding:9px;border:none;border-radius:9px;background:transparent;color:rgba(255,255,255,.5);font-size:13px;font-family:inherit;cursor:pointer;transition:.2s}
.tab-btn.active{background:rgba(255,255,255,.13);color:#fff;font-weight:600}
.pane{display:none;animation:fade .25s ease-out}
.pane.active{display:block}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
label{display:block;font-size:12px;color:rgba(255,255,255,.55);margin-bottom:14px}
.iwrap{position:relative;margin-top:6px}
.iwrap svg.icon{position:absolute;left:13px;top:50%;transform:translateY(-50%);opacity:.5;pointer-events:none}
.iwrap input{width:100%;padding:12px 42px 12px 41px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.11);border-radius:12px;color:#fff;font-size:14px;font-family:inherit;outline:none;transition:border-color .2s,box-shadow .2s}
.iwrap input::placeholder{color:rgba(255,255,255,.28)}
.iwrap input:focus{border-color:#6d8dff;box-shadow:0 0 0 3px rgba(109,141,255,.22)}
.eye{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;opacity:.45;padding:6px;line-height:0;transition:.2s}
.eye:hover{opacity:.95}
.btn-primary{width:100%;padding:12.5px;border:none;border-radius:12px;background:linear-gradient(135deg,#4f7cff,#8a5cf6);color:#fff;font-size:14px;font-weight:700;font-family:inherit;letter-spacing:.2px;cursor:pointer;transition:filter .15s,transform .15s,box-shadow .15s;box-shadow:0 12px 30px rgba(93,108,255,.35)}
.btn-primary:hover{filter:brightness(1.12);transform:translateY(-1px)}
.btn-primary:active{transform:none}
.hint{font-size:11.5px;color:rgba(255,255,255,.32);text-align:center;margin-top:14px;line-height:1.5}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<div class="blob b1"></div><div class="blob b2"></div><div class="blob b3"></div>
<section class="card">
<div class="mark"><svg width="30" height="30" viewBox="0 0 64 64" fill="none" aria-hidden="true"><path d="M32 5 L55 12.5 V29 C55 43.5 46.5 52.5 32 58.5 C17.5 52.5 9 43.5 9 29 V12.5 Z" stroke="#fff" stroke-width="4" stroke-linejoin="round"/><path d="M32 5 L55 12.5 V29 C55 43.5 46.5 52.5 32 58.5 Z" fill="rgba(255,255,255,.14)"/><path d="M15 36 H25.5 L31.5 26 H49" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><circle cx="15" cy="36" r="2.6" fill="#fff"/><circle cx="49" cy="26" r="3.6" fill="#c7d8ff"/></svg></div>
<h1>PxProxy</h1>
<p class="sub">Acceso seguro al proxy corporativo</p>
`

const loginPageFoot = `
<p class="hint">Sesion protegida con firma HMAC-SHA256.<br>Tu actividad quedara registrada.</p>
</section>
<script>
function pxTab(b,id){document.querySelectorAll('.tab-btn').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.pane').forEach(p=>p.classList.remove('active'));b.classList.add('active');document.getElementById(id).classList.add('active');var f=document.getElementById(id).querySelector('input:not([type=hidden])');if(f)f.focus()}
function pxToggle(b){var i=b.parentElement.querySelector('input');i.type=i.type==='password'?'text':'password';b.style.opacity=i.type==='password'?'.45':'.95'}
</script>
</body>
</html>`

const svgWarn = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ffb3ad" stroke-width="2" stroke-linecap="round"><path d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>`
const svgUser = `<svg class="icon" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6 8-6s8 2 8 6"/></svg>`
const svgLock = `<svg class="icon" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>`
const svgEye = `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>`

func msBtnHTML() string {
	return `<a class="ms-btn" href="/auth/login?return={{RETURN}}"><svg width="20" height="20" viewBox="0 0 21 21" aria-hidden="true"><rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg>Continuar con Microsoft</a>`
}

func ldapPaneHTML(active bool, returnRaw string) string {
	cls := map[bool]string{true: "pane active", false: "pane"}[active]
	return `<form id="pane-ad" class="` + cls + `" method="post" action="/auth/login/ldap">
<input type="hidden" name="return" value="` + returnRaw + `">
<label>Usuario de dominio<div class="iwrap">` + svgUser + `<input name="username" type="text" placeholder="usuario o usuario@midominio.local" autocomplete="username" required></div></label>
<label>Contrasena<div class="iwrap">` + svgLock + `<input name="password" type="password" placeholder="Tu contrasena de dominio" autocomplete="current-password" required><button type="button" class="eye" onclick="pxToggle(this)" aria-label="Mostrar contrasena">` + svgEye + `</button></div></label>
<button class="btn-primary" type="submit">Iniciar sesion con Active Directory</button>
</form>`
}

func localPaneHTML(active bool, user, returnRaw string) string {
	cls := map[bool]string{true: "pane active", false: "pane"}[active]
	return `<form id="pane-local" class="` + cls + `" method="post" action="/auth/login/local">
<input type="hidden" name="return" value="` + returnRaw + `">
<label>Usuario<div class="iwrap">` + svgUser + `<input name="username" type="text" value="` + user + `" autocomplete="username" required></div></label>
<label>Contrasena<div class="iwrap">` + svgLock + `<input name="password" type="password" placeholder="********" autocomplete="current-password" required><button type="button" class="eye" onclick="pxToggle(this)" aria-label="Mostrar contrasena">` + svgEye + `</button></div></label>
<button class="btn-primary" type="submit">Entrar al panel</button>
</form>`
}

const tabsHTML = `<div class="tabs">
<button type="button" class="tab-btn" onclick="pxTab(this,'pane-ad')">AD del dominio</button>
<button type="button" class="tab-btn" onclick="pxTab(this,'pane-local')">Cuenta local</button>
</div>`

func (a *Admin) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if !a.auth.EntraEnabled() {
		_ = a.auth.Reload()
	}
	cfg := a.store.Get()
	en := a.auth.EntraEnabled()
	lp := cfg.LDAP.Enabled
	lo := cfg.LocalAdmin.Enabled
	switch {
	case en && !lp && !lo:
		a.auth.StartEntraLogin(w, r)
		return
	case !en && !lp && !lo:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(loginPageHead + `<p class="alert">` + svgWarn + `<span>No hay ningun metodo de autenticacion configurado.</span></p>` + loginPageFoot))
		return
	}
	returnRaw := html.EscapeString(auth.SanitizeReturnURL(r.URL.Query().Get("return")))
	var b strings.Builder
	b.WriteString(loginPageHead)
	if e := r.URL.Query().Get("error"); e != "" {
		b.WriteString(`<p class="alert">` + svgWarn + `<span>` + html.EscapeString(e) + `</span></p>`)
	}
	if en {
		b.WriteString(strings.ReplaceAll(msBtnHTML(), "{{RETURN}}", returnRaw))
		b.WriteString(`<div class="divider">o continuar con</div>`)
	}
	switch {
	case lp && lo:
		b.WriteString(tabsHTML)
		b.WriteString(ldapPaneHTML(!en, returnRaw))
		b.WriteString(localPaneHTML(en, html.EscapeString(cfg.LocalAdmin.Username), returnRaw))
	case lp:
		b.WriteString(ldapPaneHTML(true, returnRaw))
	case lo:
		b.WriteString(localPaneHTML(true, html.EscapeString(cfg.LocalAdmin.Username), returnRaw))
	}
	b.WriteString(loginPageFoot)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (a *Admin) loginBlocked(w http.ResponseWriter, r *http.Request, userKey string, until time.Time, method string) {
	mins := int(time.Until(until).Minutes()) + 1
	a.audit.Log("login_blocked", security.ClientIP(r), userKey, "metodo="+method)
	http.Redirect(w, r, "/auth/login?error="+url.QueryEscape(fmt.Sprintf("Demasiados intentos fallidos. Espera %d minuto(s).", mins)), http.StatusFound)
}

func (a *Admin) handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Get()
	if !cfg.LocalAdmin.Enabled {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		jsonErr(w, http.StatusBadRequest, "formulario invalido")
		return
	}
	ip := security.ClientIP(r)
	username := strings.TrimSpace(r.PostFormValue("username"))
	ipKey := "ip|" + ip
	userKey := "u|local|" + strings.ToLower(username)
	if ok, until := a.limIP.Allowed(ipKey); !ok {
		a.loginBlocked(w, r, ipKey, until, "local")
		return
	}
	if ok, until := a.limUser.Allowed(userKey); !ok {
		a.loginBlocked(w, r, username, until, "local")
		return
	}
	u, err := auth.LocalLogin(cfg.LocalAdmin, username, r.PostFormValue("password"))
	if err != nil {
		a.limIP.Fail(ipKey)
		a.limUser.Fail(userKey)
		a.audit.Log("login_failed", ip, username, "metodo=local")
		logger := a.logger
		logger.Printf("login local fallido desde %s (%s)", ip, username)
		http.Redirect(w, r, "/auth/login?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	a.limIP.Reset(ipKey)
	a.limUser.Reset(userKey)
	a.audit.Log("login_success", ip, u.Email, "metodo=local")
	a.auth.CompleteLogin(w, r, u, r.FormValue("return"))
}

func validatePasswordStrength(pw string) string {
	if len(pw) < 12 {
		return "la contrasena debe tener al menos 12 caracteres"
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range pw {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return "la contrasena debe incluir mayusculas, minusculas, numeros y simbolos"
	}
	lower := strings.ToLower(pw)
	norm := strings.Map(func(r rune) rune {
		switch r {
		case '0':
			return 'o'
		case '1':
			return 'i'
		case '3':
			return 'e'
		case '4':
			return 'a'
		case '5':
			return 's'
		case '7':
			return 't'
		case '@':
			return 'a'
		case '$':
			return 's'
		}
		return r
	}, lower)
	for _, weak := range []string{"password", "contrasena", "123456", "qwerty", "admin", "pxproxy"} {
		if strings.Contains(lower, weak) || strings.Contains(norm, weak) {
			return "la contrasena contiene patrones demasiado comunes"
		}
	}
	return ""
}

func (a *Admin) handleLocalPassword(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Get()
	if !cfg.LocalAdmin.Enabled {
		jsonErr(w, http.StatusBadRequest, "la cuenta local esta deshabilitada")
		return
	}
	var body struct {
		Current string `json:"current_password"`
		Next    string `json:"new_password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeErr(w, err)
		return
	}
	if msg := validatePasswordStrength(body.Next); msg != "" {
		jsonErr(w, http.StatusBadRequest, msg)
		return
	}
	if config.CheckPassword(cfg.LocalAdmin.PasswordHash, body.Current) != nil {
		a.audit.Log("password_change_failed", security.ClientIP(r), cfg.LocalAdmin.Username, "contrasena actual incorrecta")
		jsonErr(w, http.StatusUnauthorized, "la contrasena actual no es correcta")
		return
	}
	hash, err := config.HashPassword(body.Next)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "no se pudo generar el hash")
		return
	}
	if err := a.store.Update(func(c *config.Config) { c.LocalAdmin.PasswordHash = hash }); err != nil {
		jsonErr(w, http.StatusInternalServerError, "no se pudo guardar")
		return
	}
	a.audit.Log("password_changed", security.ClientIP(r), cfg.LocalAdmin.Username, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

const totpPageHead = loginPageHead

func (a *Admin) twofaError(errMsg string) string {
	if errMsg == "" {
		return ""
	}
	return `<p class="alert">` + svgWarn + `<span>` + html.EscapeString(errMsg) + `</span></p>`
}

func (a *Admin) handle2FAPage(w http.ResponseWriter, r *http.Request) {
	if _, err := a.auth.PendingFromRequest(r); err != nil {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	page := totpPageHead + a.twofaError(r.URL.Query().Get("error")) + `
<h1 style="margin-top:6px">Verificacion en dos pasos</h1>
<p class="sub">Introduce el codigo de 6 digitos de tu app authenticator.</p>
<form method="post" action="/auth/2fa/verify">
<div class="iwrap" style="margin-top:18px"><input name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" placeholder="000000" autocomplete="one-time-code" required></div>
<button class="btn-primary" type="submit" style="margin-top:16px">Verificar</button>
</form>` + loginPageFoot
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func (a *Admin) handle2FAVerify(w http.ResponseWriter, r *http.Request) {
	pend, err := a.auth.PendingFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/auth/login?error="+url.QueryEscape("sesion de verificacion expirada"), http.StatusFound)
		return
	}
	key := strings.ToLower(strings.TrimSpace(pend.Email))
	cfg := a.store.Get()
	sec, ok := cfg.TOTP.Secrets[key]
	if !ok || !sec.Confirmed {
		http.Redirect(w, r, "/auth/2fa/enroll", http.StatusFound)
		return
	}
	tKey := "totp|" + key
	if ok2, until := a.limTOTP.Allowed(tKey); !ok2 {
		a.audit.Log("totp_blocked", security.ClientIP(r), pend.Email, "")
		mins := int(time.Until(until).Minutes()) + 1
		http.Redirect(w, r, "/auth/2fa?error="+url.QueryEscape(fmt.Sprintf("Demasiados intentos. Espera %d minuto(s).", mins)), http.StatusFound)
		return
	}
	_ = r.ParseForm()
	code := strings.TrimSpace(r.PostFormValue("code"))
	if !auth.VerifyTOTPCode(sec.Secret, code) {
		a.limTOTP.Fail(tKey)
		a.audit.Log("totp_failed", security.ClientIP(r), pend.Email, "")
		http.Redirect(w, r, "/auth/2fa?error="+url.QueryEscape("codigo incorrecto"), http.StatusFound)
		return
	}
	a.limTOTP.Reset(tKey)
	u := &pend.UserClaims
	token, terr := a.auth.IssueSession(u)
	if terr != nil {
		http.Error(w, "error interno", http.StatusInternalServerError)
		return
	}
	a.auth.ClearPendingCookie(w, r)
	a.auth.WriteSessionCookie(w, r, token)
	a.audit.Log("totp_success", security.ClientIP(r), pend.Email, "segundo factor aceptado")
	http.Redirect(w, r, a.auth.RedirectAfterAuth(u, pend.Return), http.StatusFound)
}

func (a *Admin) handle2FAEnrollPage(w http.ResponseWriter, r *http.Request) {
	pend, err := a.auth.PendingFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/auth/login?error="+url.QueryEscape("sesion de verificacion expirada"), http.StatusFound)
		return
	}
	key := strings.ToLower(strings.TrimSpace(pend.Email))
	cfg := a.store.Get()
	if sec, ok := cfg.TOTP.Secrets[key]; ok && sec.Confirmed {
		http.Redirect(w, r, "/auth/2fa", http.StatusFound)
		return
	}
	sec, err := a.auth.EnsureUnconfirmedSecret(key)
	if err != nil {
		http.Error(w, "error generando secreto TOTP", http.StatusInternalServerError)
		return
	}
	qr, qerr := a.auth.EnrollQR(pend.Email, sec.Secret)
	if qerr != nil {
		http.Error(w, "error generando QR", http.StatusInternalServerError)
		return
	}
	spaced := ""
	for i, c := range sec.Secret {
		if i > 0 && i%4 == 0 {
			spaced += " "
		}
		spaced += string(c)
	}
	page := totpPageHead + a.twofaError(r.URL.Query().Get("error")) + `
<h1 style="margin-top:6px">Configura tu segundo factor</h1>
<p class="sub">Escanea este QR con Google Authenticator, Microsoft Authenticator o similar.</p>
<div style="text-align:center;margin:18px 0"><img src="` + qr + `" width="220" height="220" alt="QR TOTP" style="border-radius:12px;background:#fff;padding:8px"></div>
<p class="sub" style="text-align:center">Clave manual: <code style="user-select:all">` + spaced + `</code></p>
<form method="post" action="/auth/2fa/enroll/confirm">
<div class="iwrap" style="margin-top:14px"><input name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" placeholder="000000" autocomplete="one-time-code" required></div>
<button class="btn-primary" type="submit" style="margin-top:16px">Confirmar y entrar</button>
</form>` + loginPageFoot
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func (a *Admin) handle2FAEnrollConfirm(w http.ResponseWriter, r *http.Request) {
	pend, err := a.auth.PendingFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/auth/login?error="+url.QueryEscape("sesion de verificacion expirada"), http.StatusFound)
		return
	}
	_ = r.ParseForm()
	key := strings.ToLower(strings.TrimSpace(pend.Email))
	if cerr := a.auth.ConfirmSecret(key, strings.TrimSpace(r.PostFormValue("code"))); cerr != nil {
		a.audit.Log("totp_enroll_failed", security.ClientIP(r), pend.Email, cerr.Error())
		http.Redirect(w, r, "/auth/2fa/enroll?error="+url.QueryEscape(cerr.Error()), http.StatusFound)
		return
	}
	u := &pend.UserClaims
	token, terr := a.auth.IssueSession(u)
	if terr != nil {
		http.Error(w, "error interno", http.StatusInternalServerError)
		return
	}
	a.auth.ClearPendingCookie(w, r)
	a.auth.WriteSessionCookie(w, r, token)
	a.audit.Log("totp_enrolled", security.ClientIP(r), pend.Email, "inscripcion completada")
	http.Redirect(w, r, a.auth.RedirectAfterAuth(u, pend.Return), http.StatusFound)
}

func (a *Admin) handleTOTPGet(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Get()
	enrolled := make([]map[string]any, 0, len(cfg.TOTP.Secrets))
	for k, s := range cfg.TOTP.Secrets {
		enrolled = append(enrolled, map[string]any{"identity": k, "confirmed": s.Confirmed})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":     cfg.TOTP.Enabled,
		"require_for": cfg.TOTP.RequireFor,
		"enrolled":    enrolled,
	})
}

func (a *Admin) handleTOTPSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RequireFor []string `json:"require_for"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeErr(w, err)
		return
	}
	err := a.store.Update(func(c *config.Config) {
		c.TOTP.Enabled = true
		c.TOTP.RequireFor = cleanList(body.RequireFor)
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "no se pudo guardar")
		return
	}
	who := r.Header.Get("X-Px-User")
	a.audit.Log("totp_settings", security.ClientIP(r), who, fmt.Sprintf("usuarios=%v", len(body.RequireFor)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Admin) handleTOTPReset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Identity string `json:"identity"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeErr(w, err)
		return
	}
	id := strings.ToLower(strings.TrimSpace(body.Identity))
	err := a.store.Update(func(c *config.Config) {
		delete(c.TOTP.Secrets, id)
		delete(c.TOTP.Secrets, id+"@local")
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "no se pudo guardar")
		return
	}
	a.audit.Log("totp_reset", security.ClientIP(r), r.Header.Get("X-Px-User"), id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func certDomains(c config.Config) []string {
	out := []string{}
	for _, d := range c.ACME.Domains {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	for _, rl := range c.Rules {
		if h := rules.NormalizeHost(rl.Host); h != "" {
			out = append(out, h)
		}
	}
	return out
}

func (a *Admin) handleCertsGet(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Get()
	writeJSON(w, http.StatusOK, map[string]any{
		"acme": map[string]any{
			"enabled":       cfg.ACME.Enabled,
			"domains":       cfg.ACME.Domains,
			"redirect_http": cfg.ACME.RedirectHTTP,
			"cache_dir":     cfg.ACME.CacheDir,
		},
		"domains": a.certs.List(certDomains(cfg)),
	})
}

func (a *Admin) handleCertsStatus(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Get()
	list := a.certs.List(certDomains(cfg))
	type row struct {
		certs.Info
		Live certs.LiveInfo `json:"live"`
	}
	rows := make([]row, 0, len(list))
	for _, i := range list {
		rows = append(rows, row{Info: i, Live: a.certs.Probe(i.Domain)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": rows})
}

func (a *Admin) handleCertACMESet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled      bool     `json:"enabled"`
		Domains      []string `json:"domains"`
		RedirectHTTP bool     `json:"redirect_http"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeErr(w, err)
		return
	}
	domains := []string{}
	for _, d := range body.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if !hostRE.MatchString(d) && !strings.HasPrefix(d, "*.") {
			if !hostRE.MatchString(strings.TrimPrefix(d, "*.")) {
				jsonErr(w, http.StatusBadRequest, "dominio invalido: "+d)
				return
			}
		}
		domains = append(domains, d)
	}
	err := a.store.Update(func(c *config.Config) {
		c.ACME.Enabled = body.Enabled
		c.ACME.Domains = domains
		c.ACME.RedirectHTTP = body.RedirectHTTP
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "no se pudo guardar")
		return
	}
	a.audit.Log("cert_acme_update", security.ClientIP(r), r.Header.Get("X-Px-User"), fmt.Sprintf("enabled=%v dominios=%d redirect=%v (cambio de listener requiere reinicio)", body.Enabled, len(domains), body.RedirectHTTP))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Admin) handleCertCustomPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain  string `json:"domain"`
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeErr(w, err)
		return
	}
	host := certs.SanitizeHost(body.Domain)
	if host == "" || !hostRE.MatchString(host) && !strings.HasPrefix(host, "*.") {
		jsonErr(w, http.StatusBadRequest, "dominio invalido")
		return
	}
	if err := a.certs.PutCustom(host, body.CertPEM, body.KeyPEM); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.audit.Log("cert_custom_upload", security.ClientIP(r), r.Header.Get("X-Px-User"), host)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Admin) handleCertCustomDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeErr(w, err)
		return
	}
	if err := a.certs.DeleteCustom(body.Domain); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.audit.Log("cert_custom_delete", security.ClientIP(r), r.Header.Get("X-Px-User"), body.Domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Admin) handleCertRenew(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeDecodeErr(w, err)
		return
	}
	if err := a.certs.Renew(body.Domain); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.audit.Log("cert_renew", security.ClientIP(r), r.Header.Get("X-Px-User"), body.Domain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "detail": "cache invalidada; el certificado se emitira/renovara en el proximo acceso HTTPS o verificacion"})
}

func (a *Admin) handleRevokeSessions(w http.ResponseWriter, r *http.Request) {
	u, _ := a.auth.SessionFromRequest(r)
	who := ""
	if u != nil {
		who = u.Email
	}
	if err := a.auth.RevokeAllSessions(); err != nil {
		jsonErr(w, http.StatusInternalServerError, "no se pudo revocar")
		return
	}
	a.audit.Log("sessions_revoked", security.ClientIP(r), who, "todas las sesiones fueron invalidadas")
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (a *Admin) handleSecurityInfo(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Get()
	writeJSON(w, http.StatusOK, map[string]any{
		"login_max_fails":     cfg.LoginMaxFails,
		"lockout_minutes":     cfg.LockoutMinutes,
		"active_lockouts":     a.limUser.ActiveLocks() + a.limIP.ActiveLocks(),
		"admin_allowed_cidrs": cfg.AdminAllowedCIDRs,
		"secure_cookies":      cfg.SecureCookies,
		"session_epoch":       cfg.SessionEpoch,
		"default_password":    cfg.LocalAdmin.IsDefaultPassword(),
	})
}

func (a *Admin) handleLDAPLogin(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Get()
	if !cfg.LDAP.Enabled {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		jsonErr(w, http.StatusBadRequest, "formulario invalido")
		return
	}
	ip := security.ClientIP(r)
	username := strings.TrimSpace(r.PostFormValue("username"))
	ipKey := "ip|" + ip
	userKey := "u|ldap|" + strings.ToLower(username)
	if ok, until := a.limIP.Allowed(ipKey); !ok {
		a.loginBlocked(w, r, ipKey, until, "ldap")
		return
	}
	if ok, until := a.limUser.Allowed(userKey); !ok {
		a.loginBlocked(w, r, username, until, "ldap")
		return
	}
	u, err := auth.LDAPLogin(cfg.LDAP, username, r.PostFormValue("password"))
	if err != nil {
		a.limIP.Fail(ipKey)
		a.limUser.Fail(userKey)
		a.audit.Log("login_failed", ip, username, "metodo=ldap")
		http.Redirect(w, r, "/auth/login?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	a.limIP.Reset(ipKey)
	a.limUser.Reset(userKey)
	a.audit.Log("login_success", ip, u.Email, "metodo=ldap")
	a.auth.CompleteLogin(w, r, u, r.FormValue("return"))
}
