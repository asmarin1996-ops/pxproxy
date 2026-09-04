package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy/internal/config"
)

// newTestAuth crea un Store sobre un directorio temporal y un Authenticator.
func newTestAuth(t *testing.T) *Authenticator {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return New(store)
}

func TestLocalAdmin2FAEnrollAndConfirm(t *testing.T) {
	a := newTestAuth(t)

	// Habilitar 2FA exigida para la identidad local "admin".
	if err := a.store.Update(func(c *config.Config) {
		c.TOTP.Enabled = true
		c.TOTP.RequireFor = []string{"admin"}
	}); err != nil {
		t.Fatalf("store.Update: %v", err)
	}

	u := &UserClaims{Sub: "local|admin", Email: "admin@local", Name: "Admin"}
	if !NeedsSecondFactor(a.store.Get(), u) {
		t.Fatalf("NeedsSecondFactor deberia ser true con 2FA exigida para admin")
	}

	key := totpKeyOf(u)
	sec, err := a.EnsureUnconfirmedSecret(key)
	if err != nil {
		t.Fatalf("EnsureUnconfirmedSecret: %v", err)
	}
	if sec.Secret == "" {
		t.Fatalf("secreto vacio generado")
	}
	if sec.Confirmed {
		t.Fatalf("el secreto nuevo no deberia estar confirmado")
	}

	now := time.Now()
	code, err := TOTPCode(sec.Secret, now)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	if err := a.ConfirmSecret(key, code); err != nil {
		t.Fatalf("ConfirmSecret con codigo vigente: %v", err)
	}

	got, _ := a.store.Get().TOTP.Secrets[key]
	if !got.Confirmed {
		t.Fatalf("el secreto deberia quedar confirmado tras el alta")
	}

	// Re-confirmar con codigo dentro de la ventana pasada (tolerancia skew).
	past := time.Now().Add(-time.Duration(totpSkew) * totpStep)
	pastCode, err := TOTPCode(sec.Secret, past)
	if err != nil {
		t.Fatalf("TOTPCode(past): %v", err)
	}
	if !VerifyTOTPCode(sec.Secret, pastCode) {
		t.Fatalf("deberia aceptar codigo dentro de la ventana de skew pasada (%ds)", totpSkew*int64(totpStep/time.Second))
	}

	// Un codigo claramente incorrecto debe fallar.
	if VerifyTOTPCode(sec.Secret, "000000") {
		t.Fatalf("codigo incorrecto aceptado")
	}
}

func TestLocalAdmin2FANotRequiredForOtherIdentity(t *testing.T) {
	a := newTestAuth(t)
	if err := a.store.Update(func(c *config.Config) {
		c.TOTP.Enabled = true
		c.TOTP.RequireFor = []string{"admin"}
	}); err != nil {
		t.Fatal(err)
	}
	other := &UserClaims{Sub: "user|local", Email: "juan@local", Name: "Juan"}
	if NeedsSecondFactor(a.store.Get(), other) {
		t.Fatalf("No deberia exigirse 2FA para una identidad no listada")
	}
}

func TestEnsureUnconfirmedSecretReusesExisting(t *testing.T) {
	a := newTestAuth(t)
	key := "admin@local"
	first, err := a.EnsureUnconfirmedSecret(key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.EnsureUnconfirmedSecret(key)
	if err != nil {
		t.Fatal(err)
	}
	if first.Secret != second.Secret {
		t.Fatalf("EnsureUnconfirmedSecret no deberia regenerar un secreto existente")
	}
}

func TestConfigTOTPRoundTripSealed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(c *config.Config) {
		c.TOTP.Secrets["admin@local"] = config.TOTPSecret{Secret: "ABC123", Confirmed: true}
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]any
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	totp, _ := persisted["totp"].(map[string]any)
	secretsRaw, _ := totp["secrets"].(map[string]any)
	first, _ := secretsRaw["admin@local"].(map[string]any)
	if first == nil {
		t.Fatalf("no se persistio el secreto TOTP")
	}
	// En disco el secreto debe estar cifrado (no en claro).
	if plain, _ := first["secret"].(string); plain == "ABC123" {
		t.Fatalf("el secreto TOTP se persistio en claro")
	}
	// En memoria debe estar descifrado.
	mem, _ := store.Get().TOTP.Secrets["admin@local"]
	if mem.Secret != "ABC123" {
		t.Fatalf("en memoria el secreto deberia estar abierto, got %q", mem.Secret)
	}
}
