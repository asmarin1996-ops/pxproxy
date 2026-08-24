package rules

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxy/internal/config"
)

func testLogger() *log.Logger {
	return log.New(&bytes.Buffer{}, "", 0)
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		" App.Local:8443 ": "app.local",
		"APP.local":        "app.local",
		"*.ejemplo.com":    "*.ejemplo.com",
		"":                 "",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestLookupExactBeatsWildcard(t *testing.T) {
	e := New(testLogger())
	e.Rebuild([]config.Rule{
		{Host: "*.corp.local", Target: "http://127.0.0.1:1", Enabled: true},
		{Host: "app.corp.local", Target: "http://127.0.0.1:2", Enabled: true},
	})
	if rt := e.lookup("app.corp.local"); rt == nil || rt.rule.Host != "app.corp.local" {
		t.Error("la regla exacta debe ganar sobre el comodin")
	}
	if rt := e.lookup("otro.corp.local"); rt == nil || rt.rule.Host != "*.corp.local" {
		t.Error("el comodin deberia capturar subdominios")
	}
	if e.lookup("desconocido.local") != nil {
		t.Error("host desconocido no debe resolver")
	}
}

func TestDisabledRuleServesHardenedPage(t *testing.T) {
	e := New(testLogger())
	e.Rebuild([]config.Rule{{Host: "caido.local", Target: "http://127.0.0.1:1", Enabled: false}})
	h := e.Handler(func(*http.Request) bool { return true }, func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest("GET", "http://caido.local/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" || !bytes.Contains([]byte(csp), []byte("script-src 'none'")) {
		t.Error("CSP endurecida ausente en pagina de bloqueo")
	}
	for _, hname := range []string{"X-Content-Type-Options", "Referrer-Policy", "Cache-Control"} {
		if rec.Header().Get(hname) == "" {
			t.Errorf("falta cabecera %s en pagina de bloqueo", hname)
		}
	}
	body := rec.Body.String()
	if !containsStr(body, "no esta accesible") || containsStr(body, "caido.local") {
		t.Error("pagina de bloqueo con mensaje incorrecto o reflexion de host")
	}
}

func TestUnknownHostIs404(t *testing.T) {
	e := New(testLogger())
	e.Rebuild(nil)
	h := e.Handler(func(*http.Request) bool { return true }, func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest("GET", "http://nadie.local/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", rec.Code)
	}
}

func containsStr(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}
