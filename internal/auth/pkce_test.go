package auth

import (
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"proxy/internal/config"
)

func TestPKCES256Vector(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := pkceS256(verifier); got != want {
		t.Errorf("pkceS256 = %s; want %s", got, want)
	}
}

func TestStartEntraLoginIncludesPKCE(t *testing.T) {
	dir := t.TempDir()
	store, err := config.Load(dir + "\\config.json")
	if err != nil {
		t.Fatal(err)
	}
	a := New(store)
	a.oauth = &oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		Endpoint:     oauth2.Endpoint{AuthURL: "https://login.example.com/authorize", TokenURL: "https://login.example.com/token"},
		RedirectURL:  "http://localhost:8000/auth/callback",
	}
	req := httptest.NewRequest("GET", "/auth/login?return=https%3A%2F%2Fapp.corp.local%2Fpanel", nil)
	rec := httptest.NewRecorder()
	a.StartEntraLogin(rec, req)
	if rec.Code != 302 {
		t.Fatalf("status = %d; want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	for _, part := range []string{"code_challenge=", "code_challenge_method=S256", "state="} {
		if !strings.Contains(loc, part) {
			t.Errorf("redirect sin %q: %s", part, loc)
		}
	}
	stateCookie := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == stateCookieName {
			stateCookie = c.Value
		}
	}
	parts := strings.SplitN(stateCookie, "|", 3)
	if len(parts) != 3 {
		t.Fatalf("cookie de estado con %d partes; want 3 (nonce|return|verifier)", len(parts))
	}
	if parts[1] != "https://app.corp.local/panel" {
		t.Errorf("returnURL = %q; want https://app.corp.local/panel", parts[1])
	}
	challengeIdx := strings.Index(loc, "code_challenge=")
	rest := loc[challengeIdx+len("code_challenge="):]
	if end := strings.IndexAny(rest, "&"); end >= 0 {
		rest = rest[:end]
	}
	if rest != pkceS256(parts[2]) {
		t.Errorf("challenge en URL no coincide con S256(verifier)")
	}
}
