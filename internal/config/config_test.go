package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxy/internal/secrets"
)

func writeConfig(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadToleratesBOM(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "\xEF\xBB\xBF"+`{"session_hours": 7}`)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("load con BOM fallo: %v", err)
	}
	if s.Get().SessionHours != 7 {
		t.Errorf("session_hours = %d; want 7", s.Get().SessionHours)
	}
}

func TestDefaultsRegenerated(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.Get()
	if cfg.LocalAdmin.Username != DefaultAdminUsername {
		t.Errorf("usuario local = %q", cfg.LocalAdmin.Username)
	}
	if CheckPassword(cfg.LocalAdmin.PasswordHash, DefaultAdminPassword) != nil {
		t.Error("la contrasena por defecto no verifica contra el hash generado")
	}
	if cfg.SessionSecret == "" {
		t.Error("session_secret vacio")
	}
}

func TestSecretsEncryptedAtRestPlaintextInMemory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	plain := s.Get().SessionSecret
	if plain == "" || secrets.IsProtected(plain) {
		t.Fatalf("secreto en memoria deberia estar en claro: %q", plain)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(data)
	if !strings.Contains(raw, `"dpapi1:`) && !strings.Contains(raw, `"enc1:`) {
		t.Error("el archivo en disco no contiene secretos cifrados (dpapi1:/enc1:)")
	}
	if strings.Contains(raw, plain) {
		t.Error("el secreto en claro aparece en el archivo en disco")
	}
	if got := s.Get().SessionSecret; got != plain {
		t.Error("el secreto en memoria cambio tras guardar")
	}
}

func TestBackupsCreatedAndPruned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < backupKeep+4; i++ {
		if err := s.Update(func(c *Config) { c.SessionEpoch++ }); err != nil {
			t.Fatal(err)
		}
	}
	bdir := filepath.Join(dir, "backups")
	ents, err := os.ReadDir(bdir)
	if err != nil {
		t.Fatalf("no hay directorio de backups: %v", err)
	}
	count := 0
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "config-") && strings.HasSuffix(e.Name(), ".json") {
			count++
		}
	}
	if count == 0 {
		t.Error("no se creo ningun backup")
	}
}

func TestSealRoundTripThroughFile(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, `{"azure":{"client_id":"x","client_secret":"mi-secreto"}}`)
	s1, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s1.Get().Azure.ClientSecret; got != "mi-secreto" {
		t.Fatalf("client_secret = %q; want mi-secreto", got)
	}
	s2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.Get().Azure.ClientSecret; got != "mi-secreto" {
		t.Errorf("recarga perdio el secreto: %q", got)
	}
}
