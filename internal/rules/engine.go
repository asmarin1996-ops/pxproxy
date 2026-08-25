package rules

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"proxy/internal/config"
	"proxy/internal/health"
)

type route struct {
	rule     config.Rule
	rp       *httputil.ReverseProxy
	disabled bool
}

type Engine struct {
	mu      sync.RWMutex
	routes  map[string]*route
	logger  *log.Logger
	health  *health.Checker
	targets []string
}

func New(logger *log.Logger) *Engine {
	return &Engine{routes: make(map[string]*route), logger: logger}
}

func (e *Engine) SetHealthChecker(hc *health.Checker) {
	e.health = hc
}

func NormalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.Index(h, ":"); i >= 0 {
		h = h[:i]
	}
	return h
}

func (e *Engine) Rebuild(list []config.Rule) {
	next := make(map[string]*route, len(list))
	targets := make([]string, 0, len(list))
	for _, rl := range list {
		host := NormalizeHost(rl.Host)
		if host == "" {
			continue
		}
		rt := &route{rule: rl, disabled: !rl.Enabled}
		if !rt.disabled {
			target, err := url.Parse(strings.TrimSpace(rl.Target))
			if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
				e.logger.Printf("regla descartada (destino invalido): %s -> %q", host, rl.Target)
				continue
			}
			tgt := target
			tgtStr := tgt.String()
			targets = append(targets, tgtStr)
			rt.rp = &httputil.ReverseProxy{
				Rewrite: func(pr *httputil.ProxyRequest) {
					pr.SetURL(tgt)
					pr.Out.Host = pr.In.Host
					pr.SetXForwarded()
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					e.logger.Printf("error %s -> %s: %v", r.Host, tgt, err)
					http.Error(w, "502: el servicio de destino no responde", http.StatusBadGateway)
				},
			}
		}
		next[host] = rt
	}
	e.mu.Lock()
	e.routes = next
	e.targets = targets
	e.mu.Unlock()
	if e.health != nil {
		e.health.SetTargets(targets)
	}
}

func (e *Engine) lookup(host string) *route {
	key := NormalizeHost(host)
	e.mu.RLock()
	defer e.mu.RUnlock()
	if rt, ok := e.routes[key]; ok {
		return rt
	}
	var best *route
	bestLen := 0
	for k, rt := range e.routes {
		if !strings.HasPrefix(k, "*.") {
			continue
		}
		suffix := k[1:]
		if strings.HasSuffix(key, suffix) && len(k) > bestLen {
			best = rt
			bestLen = len(k)
		}
	}
	return best
}

const blockedPage = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Dominio no accesible</title>
<style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f172a;color:#e2e8f0;font-family:"Segoe UI",system-ui,sans-serif}
main{max-width:34rem;padding:2.5rem;text-align:center;border:1px solid #334155;border-radius:14px;background:#1e293b}
h1{margin:0 0 .5rem;font-size:1.4rem}
p{margin:.35rem 0;line-height:1.5}
.ok{display:inline-block;width:.7rem;height:.7rem;border-radius:50%;background:#22c55e;margin-right:.45rem}
.muted{color:#94a3b8;font-size:.9rem}
code{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:.15rem .4rem;font-size:.85rem}
</style>
</head>
<body>
<main>
<h1><span class="ok" aria-hidden="true"></span>Servidor operativo</h1>
<p>El servidor funciona correctamente.</p>
<p>Este dominio no esta accesible en este momento.</p>
<p class="muted">Si cree que se trata de un error, contacte al administrador del sistema.</p>
</main>
</body>
</html>`

func writeBlockedPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; img-src 'none'; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(blockedPage))
}

func (e *Engine) Handler(authCheck func(*http.Request) bool, unauthorized http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := e.lookup(r.Host)
		if rt == nil {
			http.Error(w, "404: no existe una regla de proxy para el host "+r.Host, http.StatusNotFound)
			return
		}
		if rt.disabled {
			e.logger.Printf("dominio deshabilitado: %s", NormalizeHost(r.Host))
			writeBlockedPage(w)
			return
		}
		if e.health != nil && !e.health.IsHealthy(rt.rule.Target) {
			e.logger.Printf("upstream no saludable: %s (%s)", rt.rule.Host, rt.rule.Target)
			w.Header().Set("Retry-After", "30")
			http.Error(w, "503: el servicio de destino no esta disponible temporalmente", http.StatusServiceUnavailable)
			return
		}
		if rt.rule.RequireAuth && !authCheck(r) {
			unauthorized(w, r)
			return
		}
		rt.rp.ServeHTTP(w, r)
	})
}

func (e *Engine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.routes)
}

func (e *Engine) TargetHealth() []health.Status {
	if e.health == nil {
		return nil
	}
	return e.health.Snapshot()
}
