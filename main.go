package main

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
		"os"
		"os/signal"
		"path/filepath"
		"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"proxy/internal/auth"
	"proxy/internal/certs"
	"proxy/internal/config"
	"proxy/internal/health"
	"proxy/internal/metrics"
	"proxy/internal/rules"
	"proxy/internal/security"
	"proxy/internal/server"
	pgstore "proxy/internal/store"
)

//go:embed all:web
var webFS embed.FS

func schemeOf(r *http.Request) string {
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return "https"
	}
	return "http"
}

func unauthorizedHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, fmt.Sprintf("%s://%s/auth/login?rd=%s", schemeOf(r), r.Host, url.QueryEscape(r.URL.RequestURI())), http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"autenticacion requerida"}`))
	}
}

func logMiddleware(logger *log.Logger, name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Printf("%s %s %s %s", name, r.Method, r.Host+r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

type limiterPersist struct {
	logger   *log.Logger
	path     string
	pg       *pgstore.PgBackend
	limiters map[string]*security.Limiter
}

func (p *limiterPersist) snapshots() (map[string]*security.LimiterState, int) {
	out := make(map[string]*security.LimiterState, len(p.limiters))
	total := 0
	for name, l := range p.limiters {
		st := l.Snapshot()
		out[name] = st
		total += len(st.Entries)
	}
	return out, total
}

func (p *limiterPersist) load() {
	if p.pg != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		raw, err := p.pg.LoadLocks(ctx)
		if err != nil {
			p.logger.Printf("aviso: no se pudo leer estado de bloqueos del cluster (%v); se inicia vacio", err)
			return
		}
		states := pgstore.StatesToLimiter(raw)
		n := 0
		for name, st := range states {
			if l, ok := p.limiters[name]; ok {
				l.Restore(st)
				n += len(st.Entries)
			}
		}
		if n > 0 {
			p.logger.Printf("estado de bloqueos restaurado desde el cluster (%d entradas activas)", n)
		}
		return
	}
	data, err := os.ReadFile(p.path)
	if err != nil {
		return
	}
	var file map[string]*security.LimiterState
	if err := json.Unmarshal(data, &file); err != nil {
		p.logger.Printf("aviso: estado de limitadores ilegible (%v); se inicia vacio", err)
		return
	}
	for name, st := range file {
		if l, ok := p.limiters[name]; ok {
			l.Restore(st)
		}
	}
	n := 0
	for _, st := range file {
		if st != nil {
			n += len(st.Entries)
		}
	}
	if n > 0 {
		p.logger.Printf("estado de bloqueos restaurado (%d entradas activas)", n)
	}
}

func (p *limiterPersist) save() {
	states, total := p.snapshots()
	if p.pg != nil {
		raw, err := pgstore.StatesFromLimiter(states)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := p.pg.SaveLocks(ctx, raw); err != nil && p.logger != nil {
				p.logger.Printf("aviso: no se pudo persistir estado de bloqueos en el cluster: %v", err)
			}
		}
		return
	}
	if total == 0 {
		_ = os.Remove(p.path)
		return
	}
	data, err := json.MarshalIndent(states, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(p.path, data, 0600); err != nil && p.logger != nil {
		p.logger.Printf("aviso: no se pudo persistir estado de limitadores: %v", err)
	}
}

func (p *limiterPersist) sync() {
	p.save()
	if p.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := p.pg.LoadLocks(ctx)
	if err != nil {
		return
	}
	for name, st := range pgstore.StatesToLimiter(raw) {
		if l, ok := p.limiters[name]; ok {
			l.Restore(st)
		}
	}
}

func attachPostgres(logger *log.Logger, st *config.Store, dsn string) (*pgstore.PgBackend, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	b, err := pgstore.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := st.SetBackend(ctx, b); err != nil {
		b.Close()
		return nil, err
	}
	return b, nil
}

func autoBackupBD(logger *log.Logger, pgB *pgstore.PgBackend, dir string, keep int) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	data, err := pgB.SnapshotToJSON(ctx)
	if err != nil {
		logger.Printf("aviso: backup automatico de BD fallo: %v", err)
		return
	}
	name, werr := pgstore.WriteBackupFile(dir, data)
	if werr != nil {
		logger.Printf("aviso: backup automatico de BD no se pudo escribir: %v", werr)
		return
	}
	pgstore.PruneBackupFiles(dir, keep)
	var snap pgstore.Snapshot
	_ = json.Unmarshal(data, &snap)
	logger.Printf("backup automatico de BD creado: %s %v", filepath.Base(name), snap.Counts)
}

var version = "dev"

func main() {
	cfgPath := flag.String("config", "config.json", "ruta al archivo de configuracion")
	adminPort := flag.Int("admin-port", 0, "puerto del panel (sobrescribe la configuracion, no se persiste)")
	httpPort := flag.Int("proxy-http-port", 0, "puerto HTTP del proxy (sobrescribe la configuracion, no se persiste)")
	httpsPort := flag.Int("proxy-https-port", 0, "puerto HTTPS del proxy (sobrescribe la configuracion, no se persiste)")
	backupBD := flag.String("backup-bd", "", "copia de seguridad de la BD hacia el fichero indicado y sale")
	restoreBD := flag.String("restore-bd", "", "restaura la BD desde el fichero indicado y sale")
	flag.Parse()

	logger := log.New(os.Stdout, "[pxproxy] ", log.LstdFlags)
	logger.Printf("PxProxy v%s iniciando (%s/%s)", version, runtime.GOOS, runtime.GOARCH)

	store, err := config.Load(*cfgPath)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}

	var pgB *pgstore.PgBackend
	cfg := store.Get()
	if strings.EqualFold(strings.TrimSpace(cfg.Storage.Backend), "postgres") && cfg.Storage.DSN != "" {
		for attempt := 1; attempt <= 3; attempt++ {
			b, aerr := attachPostgres(logger, store, cfg.Storage.DSN)
			if aerr == nil {
				pgB = b
				cfg = store.Get()
				logger.Printf("almacenamiento postgres activo (cluster compartido; sesiones y bloqueos sincronizados)")
				break
			}
			if errors.Is(aerr, config.ErrKeyMismatch) {
				logger.Fatalf("almacenamiento postgres: %v; copia el secrets.key del cluster a este nodo", aerr)
			}
			logger.Printf("aviso: intento %d/3 de conexion al backend postgres fallo: %v", attempt, aerr)
			time.Sleep(2 * time.Second)
		}
		if pgB == nil {
			logger.Printf("ADVERTENCIA: se continua en modo fichero degradado (sin cluster); corrige el acceso a la BD y reinicia el servicio")
		}
	} else if strings.EqualFold(strings.TrimSpace(cfg.Storage.Backend), "postgres") {
		logger.Printf("storage.backend=postgres pero storage.dsn esta vacio; se usa modo fichero")
	}

	if *backupBD != "" || *restoreBD != "" {
		if pgB == nil {
			logger.Fatal("las operaciones de backup/restore requieren storage.backend=postgres activo")
		}
		bctx, bcancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer bcancel()
		if *backupBD != "" {
			data, err := pgB.SnapshotToJSON(bctx)
			if err != nil {
				logger.Fatalf("backup de BD: %v", err)
			}
			if err := os.WriteFile(*backupBD, data, 0600); err != nil {
				logger.Fatalf("escribiendo backup: %v", err)
			}
			var snap pgstore.Snapshot
			_ = json.Unmarshal(data, &snap)
			logger.Printf("BACKUP OK -> %s (%v)", *backupBD, snap.Counts)
			return
		}
		data, err := os.ReadFile(*restoreBD)
		if err != nil {
			logger.Fatalf("leyendo backup: %v", err)
		}
		done, rerr := pgB.RestoreFromJSON(bctx, data)
		if rerr != nil {
			logger.Fatalf("restore de BD: %v", rerr)
		}
		logger.Printf("RESTORE OK desde %s: %v; los nodos recargaran la configuracion en segundos", *restoreBD, done)
		return
	}

	engine := rules.New(logger)
	hcCfg := cfg.HealthCheck
	if hcCfg.Enabled || hcCfg.IntervalSec > 0 || hcCfg.Failures > 0 {
		hc := health.New(
			time.Duration(hcCfg.IntervalSec)*time.Second,
			time.Duration(hcCfg.TimeoutSec)*time.Second,
			hcCfg.Failures,
			logger,
		)
		hc.SetOnChange(func(target string, healthy bool) {
			snap := hc.Snapshot()
			m := make(map[string]bool, len(snap))
			for _, s := range snap {
				m[s.Target] = s.Healthy
			}
			metrics.Default.SetUpstreamHealth(m)
		})
		hc.Start(context.Background())
		engine.SetHealthChecker(hc)
		logger.Printf("health checks de upstreams activos (intervalo: %ds, timeout: %ds, fallos antes de marcar down: %d)", hcCfg.IntervalSec, hcCfg.TimeoutSec, hcCfg.Failures)
	}
	authn := auth.New(store)
	if err := authn.Reload(); err != nil {
		logger.Printf("aviso: Entra ID no disponible aun: %v", err)
	}

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		logger.Fatalf("recursos web embebidos: %v", err)
	}

	audit, err := security.OpenAudit("audit.log", 10<<20)
	if err != nil {
		logger.Fatalf("log de auditoria: %v", err)
	}
	defer audit.Close()
	if pgB != nil {
		audit.SetSink(func(e security.AuditEntry) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if aerr := pgB.AppendAudit(ctx, e.Event, e.IP, e.User, e.Detail); aerr != nil {
				logger.Printf("aviso: evento de auditoria no replicado al cluster (%s): %v", e.Event, aerr)
			}
		})
	}

	cfg = store.Get()
	if *adminPort > 0 {
		cfg.AdminPort = *adminPort
	}
	if *httpPort > 0 {
		cfg.ProxyHTTPPort = *httpPort
	}
	if *httpsPort > 0 {
		cfg.ProxyHTTPSPort = *httpsPort
	}
	if cfg.LocalAdmin.Enabled && cfg.LocalAdmin.IsDefaultPassword() {
		logger.Printf("ADVERTENCIA: la cuenta local usa la contrasena por defecto (%s / %s); cambiala desde el panel lo antes posible", config.DefaultAdminUsername, config.DefaultAdminPassword)
	}
	if cfg.LDAP.Enabled && cfg.LDAP.InsecureTLS {
		logger.Printf("ADVERTENCIA: LDAP configurado con validacion TLS deshabilitada; usa ldaps con certificado valido en produccion")
	}

	certMgr, err := certs.New("certs", cfg.ProxyHTTPSPort, logger)
	if err != nil {
		logger.Fatalf("directorio de certificados: %v", err)
	}

	lockDur := time.Duration(cfg.LockoutMinutes) * time.Minute
	winDur := 15 * time.Minute
	limIP := security.NewLimiter(cfg.LoginMaxFails, winDur, lockDur)
	limUser := security.NewLimiter(cfg.LoginMaxFails, winDur, lockDur)
	limTOTP := security.NewLimiter(6, 10*time.Minute, 10*time.Minute)
	limiters := map[string]*security.Limiter{"ip": limIP, "user": limUser, "totp": limTOTP}
	lp := &limiterPersist{logger: logger, path: "limiters.json", pg: pgB, limiters: limiters}
	lp.load()
	defer lp.save()
	saveStop := make(chan struct{})
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				lp.sync()
			case <-saveStop:
				return
			}
		}
	}()
	defer close(saveStop)

	admin := server.New(store, engine, authn, certMgr, sub, logger, audit, limIP, limUser, limTOTP)
	admin.SetMetrics(metrics.Default)
	admin.SetHealthDetail(func() map[string]any {
		name, ok, ver := store.BackendStatus()
		return map[string]any{"storage": map[string]any{"backend": name, "ok": ok, "version": ver}}
	})
	engine.SetTLSLax(cfg.InsecureUpstream)
	engine.Rebuild(cfg.Rules)

	if pgB != nil {
		bdBackupDir := filepath.Join(filepath.Dir(*cfgPath), "backups", "bd")
		interval := time.Duration(cfg.Storage.BackupIntervalMinutes) * time.Minute
		if interval > 0 {
			go func() {
				time.Sleep(time.Minute)
				autoBackupBD(logger, pgB, bdBackupDir, cfg.Storage.BackupKeep)
				t := time.NewTicker(interval)
				defer t.Stop()
				for range t.C {
					autoBackupBD(logger, pgB, bdBackupDir, cfg.Storage.BackupKeep)
				}
			}()
			logger.Printf("backups automaticos de BD cada %d min en %s (conserva %d)", cfg.Storage.BackupIntervalMinutes, bdBackupDir, cfg.Storage.BackupKeep)
		}
		admin.SetStorageOps(
			func() (any, error) {
				bctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				data, err := pgB.SnapshotToJSON(bctx)
				if err != nil {
					return nil, err
				}
				name, werr := pgstore.WriteBackupFile(bdBackupDir, data)
				if werr != nil {
					return nil, werr
				}
				pgstore.PruneBackupFiles(bdBackupDir, cfg.Storage.BackupKeep)
				var snap pgstore.Snapshot
				_ = json.Unmarshal(data, &snap)
				return map[string]any{"file": filepath.Base(name), "counts": snap.Counts}, nil
			},
			func() []pgstore.BackupInfo { return pgstore.ListBackupFiles(bdBackupDir) },
			func(file string) (map[string]int, error) {
				clean := filepath.Base(strings.TrimSpace(file))
				if clean == "." || clean == "/" || filepath.Ext(clean) != ".json" {
					return nil, fmt.Errorf("fichero de backup no valido")
				}
				data, rerr := os.ReadFile(filepath.Join(bdBackupDir, clean))
				if rerr != nil {
					return nil, rerr
				}
				rctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				done, err := pgB.RestoreFromJSON(rctx, data)
				if err == nil {
					audit.Log("bd_restaurada", "", "", clean)
				}
				return done, err
			},
			func(file string) error {
				clean := filepath.Base(strings.TrimSpace(file))
				if clean == "." || clean == "/" || filepath.Ext(clean) != ".json" {
					return fmt.Errorf("fichero de backup no valido")
				}
				return pgstore.DeleteBackupFile(bdBackupDir, clean)
			},
		)
		watchCtx, watchCancel := context.WithCancel(context.Background())
		defer watchCancel()
		reload := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			data, lerr := pgB.Load(ctx)
			if lerr != nil {
				store.MarkBackend(false)
				logger.Printf("aviso: no se pudo sincronizar configuracion del cluster: %v", lerr)
				return
			}
			if len(data) == 0 {
				return
			}
			if rerr := store.ReloadFromBytes(data); rerr != nil {
				logger.Printf("aviso: configuracion del cluster descartada: %v", rerr)
				return
			}
			store.NoteBackendVersion(pgB.CurrentVersion())
			c := store.Get()
			engine.SetTLSLax(c.InsecureUpstream)
			engine.Rebuild(c.Rules)
			if aerr := authn.Reload(); aerr != nil {
				logger.Printf("aviso: recarga de proveedores de identidad: %v", aerr)
			}
			logger.Printf("configuracion sincronizada desde el cluster (reglas activas: %d)", len(c.Rules))
		}
		pgB.WatchChanges(watchCtx, func(string) { reload() })
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					ver, verr := pgB.Version(watchCtx)
					if verr != nil {
						store.MarkBackend(false)
						metrics.Default.SetBackendOk(false)
						continue
					}
					_, _, cur := store.BackendStatus()
					if cur != ver {
						reload()
						metrics.Default.SetBackendVersion(ver)
					} else {
						store.MarkBackend(true)
						metrics.Default.SetBackendOk(true)
						metrics.Default.SetBackendVersion(ver)
					}
				case <-watchCtx.Done():
					return
				}
			}
		}()
	}

	authCheck := func(r *http.Request) bool {
		_, err := authn.SessionFromRequest(r)
		return err == nil
	}

	pmux := http.NewServeMux()
	panelProxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("127.0.0.1:%d", cfg.AdminPort),
	})
	panelPublicHost := func() string {
		pub := strings.TrimSpace(store.Get().PanelPublicURL)
		if pub == "" {
			return ""
		}
		if u, err := url.Parse(pub); err == nil {
			return strings.ToLower(u.Host)
		}
		return ""
	}
	pmux.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) {
		rd := r.URL.Query().Get("rd")
		if !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") {
			rd = "/"
		}
		ret := fmt.Sprintf("%s://%s%s", schemeOf(r), r.Host, rd)
		if ph := panelPublicHost(); ph != "" {
			if strings.EqualFold(rules.NormalizeHost(r.Host), ph) {
				panelProxy.ServeHTTP(w, r)
				return
			}
			pub := strings.TrimSuffix(strings.TrimSpace(store.Get().PanelPublicURL), "/")
			http.Redirect(w, r, pub+"/auth/login?return="+url.QueryEscape(ret), http.StatusFound)
			return
		}
		c := store.Get()
		base := strings.TrimSuffix(c.Azure.RedirectURL, "/auth/callback")
		if base == "" || !strings.HasPrefix(base, "http") {
			base = fmt.Sprintf("http://localhost:%d", c.AdminPort)
		}
		http.Redirect(w, r, base+"/auth/login?return="+url.QueryEscape(ret), http.StatusFound)
	})
	pmux.HandleFunc("GET /auth/attach", authn.HandleAttach)
	pmux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	pmux.Handle("/", engine.Handler(authCheck, unauthorizedHandler()))

	proxyHandler := security.Chain(pmux,
		security.Recover(logger),
		security.SecureHeaders(false),
		metrics.Middleware,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var wg sync.WaitGroup
	startSrv := func(name string, srv *http.Server) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Printf("%s escuchando en %s", name, srv.Addr)
			if err := srv.ListenAndServe(); err != nil {
				if errors.Is(err, http.ErrServerClosed) {
					return
				}
				logger.Fatalf("%s no pudo iniciar (%v); revisa que el puerto este libre y reinicia", srv.Addr, err)
			}
		}()
	}

	adminSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.AdminPort),
		Handler:           logMiddleware(logger, "panel ", admin.Routes()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 15,
	}
	if cfg.PanelTLSCertFile != "" && cfg.PanelTLSKeyFile != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Printf("panel-tls escuchando en %s (certificado propio)", adminSrv.Addr)
			if err := adminSrv.ListenAndServeTLS(cfg.PanelTLSCertFile, cfg.PanelTLSKeyFile); err != nil {
				if errors.Is(err, http.ErrServerClosed) {
					return
				}
				logger.Fatalf("panel no pudo iniciar con TLS (%v); revisa panel_tls_cert_file/panel_tls_key_file", err)
			}
		}()
		if !cfg.SecureCookies {
			logger.Printf("ADVERTENCIA: el panel sirve por HTTPS pero secure_cookies=false; activalo para forzar cookies Secure")
		}
	} else {
		logger.Printf("panel sin TLS propio; protege el puerto %d con firewall/CIDR o configura panel_tls_cert_file", cfg.AdminPort)
		startSrv("panel  ", adminSrv)
	}

	httpHandler := http.Handler(proxyHandler)
	useACME := cfg.ACME.Enabled
	var acmeMgr *autocert.Manager
	var acmeCache autocert.Cache
	hostAllowedACME := func(host string) bool {
		h := strings.ToLower(strings.TrimSpace(host))
		if h == "" {
			return false
		}
		c := store.Get()
		for _, d := range c.ACME.Domains {
			if strings.EqualFold(strings.TrimSpace(d), h) {
				return true
			}
		}
		for _, rl := range c.Rules {
			if rules.NormalizeHost(rl.Host) == h {
				return true
			}
		}
		return false
	}
	acmeCertCached := func(host string) bool {
		if acmeCache == nil {
			return false
		}
		_, err := acmeCache.Get(context.Background(), host)
		return err == nil
	}
	if useACME {
		acmeCache = autocert.DirCache(cfg.ACME.CacheDir)
		acmeMgr = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			HostPolicy: func(ctx context.Context, host string) error {
				if hostAllowedACME(host) {
					return nil
				}
				return fmt.Errorf("dominio %q no autorizado para emision ACME", host)
			},
			Cache: acmeCache,
		}
		certMgr.SetACMEForgetter(func(domain string) {
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for _, key := range []string{domain, domain + "+tls-cert", "tls-cert-" + domain} {
				_ = acmeCache.Delete(fctx, key)
			}
			logger.Printf("cache ACME invalidada para %s; se emitira uno nuevo en el proximo acceso", domain)
		})
		challenge := acmeMgr.HTTPHandler(nil)
		httpHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
				challenge.ServeHTTP(w, r)
				return
			}
			host := rules.NormalizeHost(r.Host)
			if store.Get().ACME.RedirectHTTP {
				hasCert := certMgr.HasCustom(host) || acmeCertCached(host)
				if hasCert {
					http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusFound)
					return
				}
			}
			proxyHandler.ServeHTTP(w, r)
		})
		logger.Printf("ACME habilitado (dominios de reglas + %d configurados)", len(store.Get().ACME.Domains))
	}

	httpSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.ProxyHTTPPort),
		Handler:           logMiddleware(logger, "proxy  ", httpHandler),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	startSrv("proxy-http", httpSrv)

	var tlsSrv *http.Server
	useTLSMgr := useACME || certMgr.CustomCount() > 0
	switch {
	case useTLSMgr:
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if c, ok := certMgr.CustomCertificate(hello); ok {
					return c, nil
				}
				if acmeMgr != nil {
					host := rules.NormalizeHost(hello.ServerName)
					if host != "" && !acmeCertCached(host) && !hostAllowedACME(host) {
						return nil, fmt.Errorf("dominio %q sin certificado", hello.ServerName)
					}
					type certRes struct {
						c   *tls.Certificate
						err error
					}
					ch := make(chan certRes, 1)
					go func(h *tls.ClientHelloInfo) {
						c, err := acmeMgr.GetCertificate(h)
						ch <- certRes{c, err}
					}(hello)
					select {
					case cr := <-ch:
						return cr.c, cr.err
					case <-time.After(30 * time.Second):
						return nil, fmt.Errorf("timeout emitiendo cert ACME para %q; reintenta en unos segundos", host)
					}
				}
				return nil, fmt.Errorf("sin certificado para %q", hello.ServerName)
			},
		}
		tlsSrv = &http.Server{
			Addr:              fmt.Sprintf(":%d", cfg.ProxyHTTPSPort),
			Handler:           logMiddleware(logger, "proxy-tls", proxyHandler),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 16,
			TLSConfig:         tlsCfg,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Printf("proxy-https escuchando en %s (gestor de certificados activo)", tlsSrv.Addr)
			if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Printf("proxy-https: %v", err)
			}
		}()
	case cfg.TLSCertFile != "" && cfg.TLSKeyFile != "":
		tlsSrv = &http.Server{
			Addr:              fmt.Sprintf(":%d", cfg.ProxyHTTPSPort),
			Handler:           logMiddleware(logger, "proxy-tls", proxyHandler),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 16,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Printf("proxy-https escuchando en %s", tlsSrv.Addr)
			if err := tlsSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Printf("proxy-https: %v", err)
			}
		}()
	default:
		logger.Printf("proxy-https deshabilitado (sin certificado ni ACME configurado)")
	}

	<-ctx.Done()
	logger.Printf("apagando...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range []*http.Server{adminSrv, httpSrv, tlsSrv} {
		if s != nil {
			_ = s.Shutdown(shutCtx)
		}
	}
	wg.Wait()
	logger.Printf("listo")
}
