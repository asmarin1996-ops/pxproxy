package rules

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxy/internal/config"
	"proxy/internal/health"
)

type backend struct {
	target    *url.URL
	rp        *httputil.ReverseProxy
	weight    int
	activeConns int64
}

func (b *backend) incConns()  { atomic.AddInt64(&b.activeConns, 1) }
func (b *backend) decConns()  { atomic.AddInt64(&b.activeConns, -1) }
func (b *backend) conns() int { return int(atomic.LoadInt64(&b.activeConns)) }

type route struct {
	rule     config.Rule
	backends []*backend
	lb       *loadBalancer
	disabled bool
}

type loadBalancer struct {
	backends []*backend
	strategy string
	rr       uint64
}

func newLoadBalancer(backends []*backend, strategy string) *loadBalancer {
	return &loadBalancer{backends: backends, strategy: strategy}
}

func (lb *loadBalancer) next() *backend {
	if len(lb.backends) == 0 {
		return nil
	}
	switch lb.strategy {
	case "weighted":
		return lb.weighted()
	case "least-connections":
		return lb.leastConns()
	default:
		return lb.roundRobin()
	}
}

func (lb *loadBalancer) roundRobin() *backend {
	n := atomic.AddUint64(&lb.rr, 1)
	idx := int(n-1) % len(lb.backends)
	return lb.backends[idx]
}

func (lb *loadBalancer) weighted() *backend {
	total := 0
	for _, b := range lb.backends {
		total += b.weight
	}
	if total == 0 {
		return lb.backends[0]
	}
	n := atomic.AddUint64(&lb.rr, 1)
	pos := int(n-1) % total
	cumulative := 0
	for _, b := range lb.backends {
		cumulative += b.weight
		if pos < cumulative {
			return b
		}
	}
	return lb.backends[0]
}

func (lb *loadBalancer) leastConns() *backend {
	var best *backend
	bestConns := -1
	for _, b := range lb.backends {
		c := b.conns()
		if best == nil || c < bestConns {
			best = b
			bestConns = c
		}
	}
	return best
}

type Engine struct {
	mu              sync.RWMutex
	routes          map[string]*route
	logger          *log.Logger
	health          *health.Checker
	targets         []string
	insecureDefault bool
}

func New(logger *log.Logger) *Engine {
	return &Engine{routes: make(map[string]*route), logger: logger}
}

func (e *Engine) SetTLSLax(lax bool) {
	e.insecureDefault = lax
}

func transportFor(insecure bool) *http.Transport {
	if insecure {
		return &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		}
	}
	return http.DefaultTransport.(*http.Transport).Clone()
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

func parseTarget(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, err
	}
	return u, nil
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
			rt.backends, rt.lb = e.buildBackends(rl, host)
			for _, b := range rt.backends {
				targets = append(targets, b.target.String())
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

func (e *Engine) buildBackends(rl config.Rule, host string) ([]*backend, *loadBalancer) {
	if len(rl.Targets) > 0 {
		return e.buildMultiBackends(rl, host)
	}
	return e.buildSingleBackend(rl, host)
}

func (e *Engine) buildSingleBackend(rl config.Rule, host string) ([]*backend, *loadBalancer) {
	tgt, err := parseTarget(rl.Target)
	if err != nil || tgt == nil {
		e.logger.Printf("regla descartada (destino invalido): %s -> %q", host, rl.Target)
		return nil, nil
	}
	b := e.newBackend(tgt, 1, rl.InsecureTLS || e.insecureDefault)
	return []*backend{b}, newLoadBalancer([]*backend{b}, "round-robin")
}

func (e *Engine) buildMultiBackends(rl config.Rule, host string) ([]*backend, *loadBalancer) {
	strategy := rl.LoadBalancing
	if strategy == "" {
		strategy = "round-robin"
	}
	var backends []*backend
	for _, t := range rl.Targets {
		tgt, err := parseTarget(t.URL)
		if err != nil || tgt == nil {
			e.logger.Printf("backend descartado (destino invalido): %s -> %q", host, t.URL)
			continue
		}
		weight := t.Weight
		if weight <= 0 {
			weight = 1
		}
		backends = append(backends, e.newBackend(tgt, weight, rl.InsecureTLS || e.insecureDefault))
	}
	if len(backends) == 0 {
		return nil, nil
	}
	return backends, newLoadBalancer(backends, strategy)
}

func (e *Engine) newBackend(tgt *url.URL, weight int, insecureTLS bool) *backend {
	tgtCopy := *tgt
	b := &backend{target: &tgtCopy, weight: weight}
	b.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&tgtCopy)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		Transport: transportFor(insecureTLS),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			b.decConns()
			e.logger.Printf("error %s -> %s: %v", r.Host, &tgtCopy, err)
			http.Error(w, "502: el servicio de destino no responde", http.StatusBadGateway)
		},
		ModifyResponse: func(resp *http.Response) error {
			b.decConns()
			return nil
		},
	}
	return b
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
		if rt.lb != nil && len(rt.lb.backends) > 1 {
			b := rt.lb.next()
			if b == nil {
				http.Error(w, "503: sin backends disponibles", http.StatusServiceUnavailable)
				return
			}
			if e.health != nil && !e.health.IsHealthy(b.target.String()) {
				e.logger.Printf("backend no saludable: %s -> %s", rt.rule.Host, b.target)
				w.Header().Set("Retry-After", "30")
				http.Error(w, "503: el servicio de destino no esta disponible temporalmente", http.StatusServiceUnavailable)
				return
			}
			if rt.rule.RequireAuth && !authCheck(r) {
				unauthorized(w, r)
				return
			}
			b.incConns()
			b.rp.ServeHTTP(w, r)
			return
		}
		if e.health != nil && len(rt.backends) > 0 && !e.health.IsHealthy(rt.backends[0].target.String()) {
			e.logger.Printf("upstream no saludable: %s (%s)", rt.rule.Host, rt.backends[0].target)
			w.Header().Set("Retry-After", "30")
			http.Error(w, "503: el servicio de destino no esta disponible temporalmente", http.StatusServiceUnavailable)
			return
		}
		if rt.rule.RequireAuth && !authCheck(r) {
			unauthorized(w, r)
			return
		}
		if len(rt.backends) > 0 {
			rt.backends[0].incConns()
			rt.backends[0].rp.ServeHTTP(w, r)
		}
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

type BackendLBInfo struct {
	Host        string `json:"host"`
	Strategy    string `json:"strategy"`
	Backends    int    `json:"backends"`
	Healthy     int    `json:"healthy"`
	TotalConns  int    `json:"total_conns"`
}

func (e *Engine) LoadBalancingInfo() []BackendLBInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []BackendLBInfo
	for host, rt := range e.routes {
		if rt.lb == nil || len(rt.lb.backends) <= 1 {
			continue
		}
		info := BackendLBInfo{
			Host:     host,
			Strategy: rt.lb.strategy,
			Backends: len(rt.lb.backends),
		}
		for _, b := range rt.lb.backends {
			info.TotalConns += b.conns()
			if e.health == nil || e.health.IsHealthy(b.target.String()) {
				info.Healthy++
			}
		}
		out = append(out, info)
	}
	return out
}
