package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"proxy/internal/config"
)

const (
	sessionCookieName = "px_session"
	stateCookieName   = "px_state"
	stateMaxAge       = 600
	ticketTTLSeconds  = 60
)

type UserClaims struct {
	Sub    string   `json:"sub"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups,omitempty"`
}

type sessionPayload struct {
	UserClaims
	Epoch int64 `json:"epoch"`
	Exp   int64 `json:"exp"`
}

type ticketPayload struct {
	UserClaims
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
}

type Authenticator struct {
	store    *config.Store
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

func New(store *config.Store) *Authenticator {
	return &Authenticator{store: store}
}

func (a *Authenticator) EntraEnabled() bool {
	return a.oauth != nil && a.verifier != nil
}

func (a *Authenticator) Reload() error {
	cfg := a.store.Get()
	if cfg.Azure.TenantID == "" || cfg.Azure.ClientID == "" || cfg.Azure.ClientSecret == "" {
		a.oauth = nil
		a.verifier = nil
		a.provider = nil
		return nil
	}
	issuer := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", cfg.Azure.TenantID)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		a.oauth = nil
		a.verifier = nil
		return fmt.Errorf("descubrimiento OIDC: %w", err)
	}
	a.provider = provider
	a.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.Azure.ClientID})
	redirect := cfg.Azure.RedirectURL
	if redirect == "" {
		redirect = fmt.Sprintf("http://localhost:%d/auth/callback", cfg.AdminPort)
	}
	a.oauth = &oauth2.Config{
		ClientID:     cfg.Azure.ClientID,
		ClientSecret: cfg.Azure.ClientSecret,
		RedirectURL:  redirect,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return nil
}

func (a *Authenticator) secret() []byte {
	return []byte(a.store.Get().SessionSecret)
}

func hmacSign(secret, data []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(data)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *Authenticator) IssueSession(u *UserClaims) (string, error) {
	cfg := a.store.Get()
	hours := cfg.SessionHours
	if hours <= 0 {
		hours = 12
	}
	payload, err := json.Marshal(sessionPayload{
		UserClaims: *u,
		Epoch:      int64(cfg.SessionEpoch),
		Exp:        time.Now().Add(time.Duration(hours) * time.Hour).Unix(),
	})
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	return b64 + "." + hmacSign(a.secret(), []byte(b64)), nil
}

func (a *Authenticator) ValidateSession(token string) (*UserClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("sesion malformada")
	}
	expected := hmacSign(a.secret(), []byte(parts[0]))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(parts[1])) != 1 {
		return nil, errors.New("firma invalida")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var sp sessionPayload
	if err := json.Unmarshal(raw, &sp); err != nil {
		return nil, err
	}
	if time.Now().Unix() >= sp.Exp {
		return nil, errors.New("sesion expirada")
	}
	if sp.Epoch != int64(a.store.Get().SessionEpoch) {
		return nil, errors.New("sesion revocada")
	}
	u := sp.UserClaims
	return &u, nil
}

func (a *Authenticator) SessionFromRequest(r *http.Request) (*UserClaims, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}
	return a.ValidateSession(c.Value)
}

func isSecure(r *http.Request, force bool) bool {
	return force || r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (a *Authenticator) WriteSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	cfg := a.store.Get()
	hours := cfg.SessionHours
	if hours <= 0 {
		hours = 12
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure(r, cfg.SecureCookies),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   hours * 3600,
	})
}

func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
}

func matchAllowed(value string, list []string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return false
	}
	for _, item := range list {
		it := strings.ToLower(strings.TrimSpace(item))
		if it == "" {
			continue
		}
		if strings.HasPrefix(it, "@") {
			if strings.HasSuffix(v, it) {
				return true
			}
			continue
		}
		if v == it {
			return true
		}
	}
	return false
}

func userAllowed(u *UserClaims, allowedEmails, allowedGroups []string) bool {
	if len(allowedGroups) > 0 {
		ok := false
		for _, g := range u.Groups {
			if matchAllowed(g, allowedGroups) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(allowedEmails) == 0 {
		return true
	}
	return matchAllowed(u.Email, allowedEmails)
}

func SanitizeReturnURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.String()
}

func randHex(n int) string {
	raw := make([]byte, n)
	rand.Read(raw)
	return hex.EncodeToString(raw)
}

func (a *Authenticator) RevokeAllSessions() error {
	return a.store.Update(func(c *config.Config) {
		raw := make([]byte, 32)
		rand.Read(raw)
		c.SessionSecret = hex.EncodeToString(raw)
		c.SessionEpoch++
	})
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (a *Authenticator) StartEntraLogin(w http.ResponseWriter, r *http.Request) {
	if a.oauth == nil {
		http.Error(w, "inicio de sesion con Microsoft no configurado", http.StatusServiceUnavailable)
		return
	}
	returnURL := SanitizeReturnURL(r.URL.Query().Get("return"))
	verifier := randHex(32)
	state := randHex(16) + "|" + returnURL + "|" + verifier
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/auth",
		HttpOnly: true,
		Secure:   isSecure(r, a.store.Get().SecureCookies),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   stateMaxAge,
	})
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", pkceS256(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	http.Redirect(w, r, a.oauth.AuthCodeURL(randHex(8)+"."+state, opts...), http.StatusFound)
}

func (a *Authenticator) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if a.oauth == nil || a.verifier == nil {
		http.Error(w, "inicio de sesion con Microsoft no configurado", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	if q.Get("error") != "" {
		http.Error(w, "Microsoft devolvio un error: "+q.Get("error_description"), http.StatusBadRequest)
		return
	}
	sc, err := r.Cookie(stateCookieName)
	if err != nil || sc.Value == "" {
		http.Error(w, "estado ausente; inicia de nuevo desde /auth/login", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(sc.Value, "|", 3)
	if len(parts) < 2 {
		http.Error(w, "estado invalido", http.StatusBadRequest)
		return
	}
	fullState := sc.Value
	storedNonce := parts[0]
	returnURL := SanitizeReturnURL(parts[1])
	var verifier string
	if len(parts) == 3 {
		verifier = parts[2]
	}
	if storedNonce == "" || !strings.HasSuffix(fullState, "."+q.Get("state")) {
		http.Error(w, "estado invalido (posible CSRF)", http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	if code == "" {
		http.Error(w, "codigo de autorizacion ausente", http.StatusBadRequest)
		return
	}
	exOpts := []oauth2.AuthCodeOption{}
	if verifier != "" {
		exOpts = append(exOpts, oauth2.VerifierOption(verifier))
	}
	tok, err := a.oauth.Exchange(context.Background(), code, exOpts...)
	if err != nil {
		http.Error(w, "fallo al intercambiar el codigo: "+err.Error(), http.StatusBadGateway)
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		http.Error(w, "respuesta sin id_token", http.StatusBadGateway)
		return
	}
	idToken, err := a.verifier.Verify(context.Background(), rawID)
	if err != nil {
		http.Error(w, "id_token invalido: "+err.Error(), http.StatusUnauthorized)
		return
	}
	var claims struct {
		Email             string   `json:"email"`
		PreferredUsername string   `json:"preferred_username"`
		Name              string   `json:"name"`
		Sub               string   `json:"sub"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "no se pudieron leer las claims: "+err.Error(), http.StatusUnauthorized)
		return
	}
	email := claims.Email
	if email == "" {
		email = claims.PreferredUsername
	}
	u := &UserClaims{Sub: claims.Sub, Email: email, Name: claims.Name, Groups: claims.Groups}
	cfg := a.store.Get()
	if !userAllowed(u, cfg.Azure.AllowedEmails, cfg.Azure.AllowedGroups) {
		http.Error(w, "usuario no autorizado para usar este proxy", http.StatusForbidden)
		return
	}
	a.CompleteLogin(w, r, u, returnURL)
}

func (a *Authenticator) ClearStateCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: stateCookieName, Value: "", Path: "/auth", HttpOnly: true, Secure: isSecure(r, a.store.Get().SecureCookies), SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (a *Authenticator) RedirectAfterAuth(u *UserClaims, returnURL string) string {
	if returnURL == "" {
		return "/"
	}
	target, err := url.Parse(returnURL)
	if err != nil {
		return "/"
	}
	if target.Host == "" {
		if strings.HasPrefix(returnURL, "/") && !strings.HasPrefix(returnURL, "//") {
			return returnURL
		}
		return "/"
	}
	ticket, err := a.createTicket(u, target.Hostname())
	if err != nil {
		return "/"
	}
	scheme := "http"
	if target.Scheme == "https" {
		scheme = "https"
	}
	attach := fmt.Sprintf("%s://%s/auth/attach?t=%s&rd=%s", scheme, target.Host, url.QueryEscape(ticket), url.QueryEscape(target.RequestURI()))
	return attach
}

func (a *Authenticator) createTicket(u *UserClaims, audience string) (string, error) {
	payload, err := json.Marshal(ticketPayload{
		UserClaims: *u,
		Aud:        audience,
		Exp:        time.Now().Add(ticketTTLSeconds * time.Second).Unix(),
	})
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	return b64 + "." + hmacSign(a.secret(), []byte(b64)), nil
}

func (a *Authenticator) verifyTicket(token, audience string) (*UserClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("ticket malformado")
	}
	expected := hmacSign(a.secret(), []byte(parts[0]))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(parts[1])) != 1 {
		return nil, errors.New("firma de ticket invalida")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var tp ticketPayload
	if err := json.Unmarshal(raw, &tp); err != nil {
		return nil, err
	}
	if time.Now().Unix() >= tp.Exp {
		return nil, errors.New("ticket expirado")
	}
	if !strings.EqualFold(NormalizeAudience(tp.Aud), NormalizeAudience(audience)) {
		return nil, errors.New("ticket emitido para otro host")
	}
	u := tp.UserClaims
	return &u, nil
}

func NormalizeAudience(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

func (a *Authenticator) HandleAttach(w http.ResponseWriter, r *http.Request) {
	ticket := r.URL.Query().Get("t")
	rd := r.URL.Query().Get("rd")
	u, err := a.verifyTicket(ticket, r.Host)
	if err != nil {
		http.Error(w, "no se pudo validar el inicio de sesion: "+err.Error(), http.StatusUnauthorized)
		return
	}
	token, err := a.IssueSession(u)
	if err != nil {
		http.Error(w, "error interno al emitir la sesion", http.StatusInternalServerError)
		return
	}
	a.WriteSessionCookie(w, r, token)
	if !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") {
		rd = "/"
	}
	http.Redirect(w, r, rd, http.StatusFound)
}

func (a *Authenticator) HandleLogout(w http.ResponseWriter, r *http.Request) {
	ClearSessionCookie(w)
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}
