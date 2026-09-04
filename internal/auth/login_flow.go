package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"proxy/internal/config"
)

const pendingCookieName = "px_pending"

type pendingPayload struct {
	UserClaims
	Return string `json:"return,omitempty"`
	Exp    int64  `json:"exp"`
}

func IdentityCandidates(u *UserClaims) []string {
	return identityCandidates(u)
}

func identityCandidates(u *UserClaims) []string {
	cands := []string{}
	e := strings.ToLower(strings.TrimSpace(u.Email))
	if e != "" && e != "@" {
		cands = append(cands, e)
		if at := strings.Index(e, "@"); at > 0 && !strings.HasSuffix(e, "@local") {
			cands = append(cands, e[:at])
		}
	}
	if i := strings.LastIndex(u.Sub, "|"); i >= 0 && i+1 < len(u.Sub) {
		if suf := strings.ToLower(strings.TrimSpace(u.Sub[i+1:])); suf != "" {
			cands = append(cands, suf)
		}
	}
	return cands
}

func NeedsSecondFactor(cfg config.Config, u *UserClaims) bool {
	if !cfg.TOTP.Enabled {
		return false
	}
	for _, c := range identityCandidates(u) {
		if matchAllowed(c, cfg.TOTP.RequireFor) {
			return true
		}
	}
	return false
}

func totpKeyOf(u *UserClaims) string {
	return strings.ToLower(strings.TrimSpace(u.Email))
}

func (a *Authenticator) IssuePending(u *UserClaims, returnURL string) (string, error) {
	payload, err := json.Marshal(pendingPayload{UserClaims: *u, Return: returnURL, Exp: time.Now().Add(5 * time.Minute).Unix()})
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	return b64 + "." + hmacSign(a.secret(), []byte(b64)), nil
}

func (a *Authenticator) ValidatePending(token string) (*pendingPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("token malformado")
	}
	expected := hmacSign(a.secret(), []byte(parts[0]))
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var pp pendingPayload
	if err := json.Unmarshal(raw, &pp); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(parts[1])) != 1 {
		return nil, errors.New("firma invalida")
	}
	if time.Now().Unix() >= pp.Exp {
		return nil, errors.New("desafio expirado; inicia sesion de nuevo")
	}
	return &pp, nil
}

func (a *Authenticator) PendingFromRequest(r *http.Request) (*pendingPayload, error) {
	c, err := r.Cookie(pendingCookieName)
	if err != nil {
		return nil, err
	}
	return a.ValidatePending(c.Value)
}

func (a *Authenticator) WritePendingCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     pendingCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure(r, a.store.Get().SecureCookies),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
}

func (a *Authenticator) ClearPendingCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: pendingCookieName, Value: "", Path: "/", HttpOnly: true, Secure: isSecure(r, a.store.Get().SecureCookies), SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (a *Authenticator) EnsureUnconfirmedSecret(key string) (config.TOTPSecret, error) {
	var sec config.TOTPSecret
	err := a.store.Update(func(c *config.Config) {
		existing, ok := c.TOTP.Secrets[key]
		if ok && existing.Secret != "" {
			sec = existing
			return
		}
		s, gerr := GenerateTOTPSecret()
		if gerr != nil {
			return
		}
		sec = config.TOTPSecret{Secret: s, Confirmed: false}
		c.TOTP.Secrets[key] = sec
	})
	// Si no se pudo generar un secreto (p.ej. fallo de crypto/rand), no debe
	// quedar un secreto vacio que rompa aguas abajo (QR invalido).
	if sec.Secret == "" && err == nil {
		_, exists := a.store.Get().TOTP.Secrets[key]
		if !exists {
			err = errors.New("no se pudo generar el secreto TOTP")
		}
	}
	return sec, err
}

func (a *Authenticator) ConfirmSecret(key, code string) error {
	cfg := a.store.Get()
	sec, ok := cfg.TOTP.Secrets[key]
	if !ok || sec.Secret == "" {
		return errors.New("no hay inscripcion pendiente")
	}
	if sec.Confirmed && !VerifyTOTPCode(sec.Secret, code) {
		return errors.New("codigo incorrecto")
	}
	if !sec.Confirmed && !VerifyTOTPCode(sec.Secret, code) {
		return errors.New("codigo incorrecto; escanea el QR y vuelve a intentar")
	}
	return a.store.Update(func(c *config.Config) {
		cur := c.TOTP.Secrets[key]
		cur.Confirmed = true
		c.TOTP.Secrets[key] = cur
	})
}

func (a *Authenticator) CompleteLogin(w http.ResponseWriter, r *http.Request, u *UserClaims, returnURL string) {
	a.ClearStateCookie(w, r)
	cfg := a.store.Get()
	if NeedsSecondFactor(cfg, u) {
		key := totpKeyOf(u)
		sec, confirmed := cfg.TOTP.Secrets[key]
		pend, err := a.IssuePending(u, SanitizeReturnURL(returnURL))
		if err != nil {
			http.Error(w, "error interno", http.StatusInternalServerError)
			return
		}
		a.WritePendingCookie(w, r, pend)
		if confirmed && sec.Confirmed {
			http.Redirect(w, r, "/auth/2fa", http.StatusFound)
			return
		}
		if _, err := a.EnsureUnconfirmedSecret(key); err != nil {
			http.Error(w, "error generando secreto TOTP", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/auth/2fa/enroll", http.StatusFound)
		return
	}
	token, err := a.IssueSession(u)
	if err != nil {
		http.Error(w, "error interno al emitir la sesion", http.StatusInternalServerError)
		return
	}
	a.WriteSessionCookie(w, r, token)
	http.Redirect(w, r, a.RedirectAfterAuth(u, returnURL), http.StatusFound)
}

func (a *Authenticator) EnrollQR(account, secret string) (string, error) {
	uri := ProvisionURI("PxProxy", account, secret)
	img, err := qrcode.Encode(uri, qrcode.Medium, 220)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(img), nil
}
