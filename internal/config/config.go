package config

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"proxy/internal/secrets"
	"proxy/internal/store"
)

const DefaultAdminUsername = "admin"
const DefaultAdminPassword = "Admin123!"

type StorageConfig struct {
	Backend               string `json:"backend"`
	DSN                   string `json:"dsn"`
	BackupIntervalMinutes int    `json:"backup_interval_minutes"`
	BackupKeep            int    `json:"backup_keep"`
}

const (
	DefaultBackupInterval = 360
	DefaultBackupKeep     = 10
)

type LocalAdminConfig struct {
	Enabled      bool   `json:"enabled"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), err
}

func CheckPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (c LocalAdminConfig) IsDefaultPassword() bool {
	if c.PasswordHash == "" {
		return false
	}
	return CheckPassword(c.PasswordHash, DefaultAdminPassword) == nil
}

type AzureConfig struct {
	TenantID      string   `json:"tenant_id"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	RedirectURL   string   `json:"redirect_url"`
	AllowedEmails []string `json:"allowed_emails"`
	AllowedGroups []string `json:"allowed_groups"`
}

type LDAPConfig struct {
	Enabled       bool     `json:"enabled"`
	URL           string   `json:"url"`
	InsecureTLS   bool     `json:"insecure_tls"`
	BaseDN        string   `json:"base_dn"`
	BindUPNSuffix string   `json:"bind_upn_suffix"`
	UserFilter    string   `json:"user_filter"`
	AllowedEmails []string `json:"allowed_emails"`
	AllowedGroups []string `json:"allowed_groups"`
}

type Rule struct {
	Host        string `json:"host"`
	Target      string `json:"target"`
	RequireAuth bool   `json:"require_auth"`
	Enabled     bool   `json:"enabled"`
}

type TOTPSecret struct {
	Secret    string `json:"secret"`
	Confirmed bool   `json:"confirmed"`
}

type TOTPConfig struct {
	Enabled    bool                  `json:"enabled"`
	RequireFor []string              `json:"require_for"`
	Secrets    map[string]TOTPSecret `json:"secrets"`
}

type ACMEConfig struct {
	Enabled      bool     `json:"enabled"`
	Domains      []string `json:"domains"`
	CacheDir     string   `json:"cache_dir"`
	RedirectHTTP bool     `json:"redirect_http"`
}

type Config struct {
	AdminPort         int              `json:"admin_port"`
	ProxyHTTPPort     int              `json:"proxy_http_port"`
	ProxyHTTPSPort    int              `json:"proxy_https_port"`
	TLSCertFile       string           `json:"tls_cert_file"`
	TLSKeyFile        string           `json:"tls_key_file"`
	PanelTLSCertFile  string           `json:"panel_tls_cert_file"`
	PanelTLSKeyFile   string           `json:"panel_tls_key_file"`
	SessionHours      int              `json:"session_hours"`
	SessionSecret     string           `json:"session_secret"`
	SessionEpoch      int              `json:"session_epoch"`
	SecureCookies     bool             `json:"secure_cookies"`
	InsecureUpstream  bool             `json:"insecure_upstream"`
	AdminAllowedCIDRs []string         `json:"admin_allowed_cidrs"`
	PanelAdmins       []string         `json:"panel_admins"`
	LoginMaxFails     int              `json:"login_max_fails"`
	LockoutMinutes    int              `json:"lockout_minutes"`
	ACME              ACMEConfig       `json:"acme"`
	Azure             AzureConfig      `json:"azure"`
	LDAP              LDAPConfig       `json:"ldap"`
	LocalAdmin        LocalAdminConfig `json:"local_admin"`
	TOTP              TOTPConfig       `json:"totp"`
	Rules             []Rule           `json:"rules"`
	Storage           StorageConfig    `json:"storage"`
}

func sealSensitive(c *Config) {
	c.SessionSecret = secrets.Seal(c.SessionSecret)
	c.Azure.ClientSecret = secrets.Seal(c.Azure.ClientSecret)
	c.Storage.DSN = secrets.Seal(c.Storage.DSN)
	for k, v := range c.TOTP.Secrets {
		v.Secret = secrets.Seal(v.Secret)
		c.TOTP.Secrets[k] = v
	}
}

func openSensitive(c *Config) {
	c.SessionSecret = secrets.Open(c.SessionSecret)
	c.Azure.ClientSecret = secrets.Open(c.Azure.ClientSecret)
	c.Storage.DSN = secrets.Open(c.Storage.DSN)
	for k, v := range c.TOTP.Secrets {
		v.Secret = secrets.Open(v.Secret)
		c.TOTP.Secrets[k] = v
	}
}

func normalize(c *Config) error {
	if c.SessionSecret == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		c.SessionSecret = hex.EncodeToString(raw)
	}
	if c.LoginMaxFails <= 0 {
		c.LoginMaxFails = 5
	}
	if c.LockoutMinutes <= 0 {
		c.LockoutMinutes = 15
	}
	if c.ACME.CacheDir == "" {
		c.ACME.CacheDir = "acme-cache"
	}
	if c.TOTP.Secrets == nil {
		c.TOTP.Secrets = map[string]TOTPSecret{}
	}
	if c.LocalAdmin.PasswordHash == "" {
		h, err := HashPassword(DefaultAdminPassword)
		if err != nil {
			return err
		}
		c.LocalAdmin.PasswordHash = h
	}
	if c.LocalAdmin.Username == "" {
		c.LocalAdmin.Username = DefaultAdminUsername
	}
	if c.Storage.BackupIntervalMinutes == 0 {
		c.Storage.BackupIntervalMinutes = DefaultBackupInterval
	}
	if c.Storage.BackupIntervalMinutes < 0 {
		c.Storage.BackupIntervalMinutes = 0
	}
	if c.Storage.BackupKeep <= 0 {
		c.Storage.BackupKeep = DefaultBackupKeep
	}
	return nil
}

var ErrKeyMismatch = errors.New("la secrets.key local no coincide con la usada para cifrar la configuracion del cluster")

func stillSealed(c *Config) bool {
	if secrets.IsProtected(c.SessionSecret) || secrets.IsProtected(c.Azure.ClientSecret) || secrets.IsProtected(c.Storage.DSN) {
		return true
	}
	for _, v := range c.TOTP.Secrets {
		if secrets.IsProtected(v.Secret) {
			return true
		}
	}
	return false
}

func decodeConfig(data []byte) (*Config, error) {
	cfg := &Config{}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if err := normalize(cfg); err != nil {
		return nil, err
	}
	openSensitive(cfg)
	if stillSealed(cfg) {
		return nil, ErrKeyMismatch
	}
	return cfg, nil
}

type Store struct {
	mu        sync.RWMutex
	saveMu    sync.Mutex
	path      string
	cfg       *Config
	backend   store.ConfigBackend
	backendOK bool
	lastVer   string
}

const backupKeep = 10

func Load(path string) (*Store, error) {
	cfg := &Config{
		AdminPort:      8000,
		ProxyHTTPPort:  80,
		ProxyHTTPSPort: 443,
		SessionHours:   12,
		Azure:          AzureConfig{RedirectURL: "http://localhost:8000/auth/callback"},
		LDAP:           LDAPConfig{UserFilter: "(sAMAccountName=%s)"},
		LocalAdmin:     LocalAdminConfig{Enabled: true, Username: DefaultAdminUsername},
		Rules:          []Rule{},
	}
	if data, err := os.ReadFile(path); err == nil {
		data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := normalize(cfg); err != nil {
		return nil, err
	}
	secrets.UseKeyFile(filepath.Join(filepath.Dir(path), "secrets.key"))
	openSensitive(cfg)
	s := &Store{path: path, cfg: cfg}
	if err := s.Save(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) SetBackend(ctx context.Context, b store.ConfigBackend) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.backend = b
	s.backendOK = true
	data, err := b.Load(ctx)
	if err != nil {
		s.backendOK = false
		return fmt.Errorf("lectura inicial del backend: %w", err)
	}
	if len(data) == 0 {
		if err := s.pushToBackend(); err != nil {
			s.backendOK = false
			return err
		}
		s.lastVer, _ = b.Version(ctx)
		return nil
	}
	remote, err := decodeConfig(data)
	if err != nil {
		return fmt.Errorf("configuracion remota ilegible: %w", err)
	}
	s.mu.Lock()
	s.cfg = remote
	s.lastVer, _ = b.Version(ctx)
	s.mu.Unlock()
	return s.persistLocalLocked()
}

func (s *Store) ReloadFromBytes(data []byte) error {
	remote, err := decodeConfig(data)
	if err != nil {
		return fmt.Errorf("configuracion remota ilegible: %w", err)
	}
	s.mu.Lock()
	s.cfg = remote
	s.mu.Unlock()
	return s.persistLocal()
}

func (s *Store) BackendStatus() (name string, ok bool, version string) {
	if s.backend == nil {
		return "file", true, ""
	}
	return s.backend.Name(), s.backendOK, s.lastVer
}

func (s *Store) MarkBackend(ok bool) { s.backendOK = ok }

func (s *Store) NoteBackendVersion(v string) {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if v != "" {
		s.lastVer = v
	}
}

func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return *s.cfg
}

func (s *Store) Save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.RLock()
	clone := *s.cfg
	if clone.TOTP.Secrets != nil {
		m := make(map[string]TOTPSecret, len(clone.TOTP.Secrets))
		for k, v := range clone.TOTP.Secrets {
			m[k] = v
		}
		clone.TOTP.Secrets = m
	}
	sealSensitive(&clone)
	data, err := json.MarshalIndent(clone, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	backupConfig(s.path)
	if err := s.writeLocal(data); err != nil {
		return err
	}
	if s.backend == nil {
		return nil
	}
	if err := s.pushToBackend(); err != nil {
		s.backendOK = false
		return fmt.Errorf("backend remoto no disponible (cambio guardado solo localmente): %w", err)
	}
	s.backendOK = true
	s.lastVer, _ = s.backend.Version(context.Background())
	return nil
}

func (s *Store) writeLocal(data []byte) error {
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) persistLocal() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	return s.persistLocalLocked()
}

func (s *Store) persistLocalLocked() error {
	s.mu.RLock()
	clone := *s.cfg
	if clone.TOTP.Secrets != nil {
		m := make(map[string]TOTPSecret, len(clone.TOTP.Secrets))
		for k, v := range clone.TOTP.Secrets {
			m[k] = v
		}
		clone.TOTP.Secrets = m
	}
	sealSensitive(&clone)
	data, err := json.MarshalIndent(clone, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	return s.writeLocal(data)
}

func (s *Store) pushToBackend() error {
	s.mu.RLock()
	clone := *s.cfg
	if clone.TOTP.Secrets != nil {
		m := make(map[string]TOTPSecret, len(clone.TOTP.Secrets))
		for k, v := range clone.TOTP.Secrets {
			m[k] = v
		}
		clone.TOTP.Secrets = m
	}
	sealSensitive(&clone)
	data, err := json.Marshal(clone)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	return s.backend.Save(context.Background(), data)
}

func backupConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	bdir := filepath.Join(filepath.Dir(path), "backups")
	if err := os.MkdirAll(bdir, 0700); err != nil {
		return
	}
	name := filepath.Join(bdir, fmt.Sprintf("config-%s.json", time.Now().Format("20060102-150405")))
	_ = os.WriteFile(name, data, 0600)
	pruneBackups(bdir)
}

func pruneBackups(bdir string) {
	ents, err := os.ReadDir(bdir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if !e.IsDir() && strings.HasPrefix(n, "config-") && strings.HasSuffix(n, ".json") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for i := 0; i < len(names)-backupKeep; i++ {
		_ = os.Remove(filepath.Join(bdir, names[i]))
	}
}

func (s *Store) Update(fn func(*Config)) error {
	s.mu.Lock()
	fn(s.cfg)
	s.mu.Unlock()
	return s.Save()
}
