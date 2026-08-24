package security

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Middleware func(http.Handler) http.Handler

func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

type attemptRecord struct {
	count       int
	first       time.Time
	lockedUntil time.Time
}

type Limiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	lockout time.Duration
	entries map[string]*attemptRecord
	stop    chan struct{}
}

func NewLimiter(max int, window, lockout time.Duration) *Limiter {
	if max <= 0 {
		max = 5
	}
	if window <= 0 {
		window = 15 * time.Minute
	}
	if lockout <= 0 {
		lockout = 15 * time.Minute
	}
	l := &Limiter{max: max, window: window, lockout: lockout, entries: make(map[string]*attemptRecord), stop: make(chan struct{})}
	go l.gc()
	return l
}

func (l *Limiter) gc() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			l.mu.Lock()
			for k, e := range l.entries {
				if time.Now().After(e.lockedUntil) && time.Since(e.first) > l.window {
					delete(l.entries, k)
				}
			}
			l.mu.Unlock()
		case <-l.stop:
			return
		}
	}
}

func (l *Limiter) Stop() { close(l.stop) }

func (l *Limiter) Allowed(key string) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return true, time.Time{}
	}
	now := time.Now()
	if now.Before(e.lockedUntil) {
		return false, e.lockedUntil
	}
	if now.Sub(e.first) > l.window {
		delete(l.entries, key)
		return true, time.Time{}
	}
	return true, time.Time{}
}

func (l *Limiter) Fail(key string) (locked bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e, ok := l.entries[key]
	if !ok || now.Sub(e.first) > l.window {
		e = &attemptRecord{first: now}
		l.entries[key] = e
	}
	e.count++
	if e.count >= l.max {
		e.lockedUntil = now.Add(l.lockout)
		return true
	}
	return false
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

func (l *Limiter) ActiveLocks() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.entries {
		if time.Now().Before(e.lockedUntil) {
			n++
		}
	}
	return n
}

type LockEntry struct {
	Count       int       `json:"count"`
	First       time.Time `json:"first"`
	LockedUntil time.Time `json:"locked_until"`
}

type LimiterState struct {
	Max     int                  `json:"max"`
	Window  time.Duration        `json:"window"`
	Lockout time.Duration        `json:"lockout"`
	Entries map[string]LockEntry `json:"entries"`
}

func (l *Limiter) Snapshot() *LimiterState {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	out := &LimiterState{
		Max:     l.max,
		Window:  l.window,
		Lockout: l.lockout,
		Entries: make(map[string]LockEntry),
	}
	for k, e := range l.entries {
		if e.count <= 0 {
			continue
		}
		if now.After(e.lockedUntil) && now.Sub(e.first) > l.window {
			continue
		}
		out.Entries[k] = LockEntry{Count: e.count, First: e.first, LockedUntil: e.lockedUntil}
	}
	return out
}

func (l *Limiter) Restore(st *LimiterState) {
	if st == nil || len(st.Entries) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, e := range st.Entries {
		if e.Count <= 0 || k == "" {
			continue
		}
		if now.After(e.LockedUntil) && now.Sub(e.First) > l.window {
			continue
		}
		if _, exists := l.entries[k]; !exists {
			l.entries[k] = &attemptRecord{count: e.Count, first: e.First, lockedUntil: e.LockedUntil}
		}
	}
}

type AuditEntry struct {
	Time   time.Time `json:"time"`
	Event  string    `json:"event"`
	IP     string    `json:"ip,omitempty"`
	User   string    `json:"user,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

type AuditLog struct {
	mu   sync.Mutex
	f    *os.File
	path string
	max  int64
	sink func(AuditEntry)
}

const auditKeepRotated = 5

func OpenAudit(path string, maxBytes int64) (*AuditLog, error) {
	if maxBytes <= 0 {
		maxBytes = 10 << 20
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &AuditLog{f: f, path: path, max: maxBytes}, nil
}

func (a *AuditLog) rotateLocked() {
	a.f.Close()
	base := filepath.Base(a.path)
	stem := strings.TrimSuffix(base, ".log")
	dir := filepath.Dir(a.path)
	stamped := filepath.Join(dir, fmt.Sprintf("%s-%s.log", stem, time.Now().Format("20060102-150405")))
	_ = os.Rename(a.path, stamped)
	ents, _ := os.ReadDir(dir)
	var rotated []string
	prefix := stem + "-"
	for _, e := range ents {
		name := e.Name()
		if !e.IsDir() && strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".log") && name != base {
			rotated = append(rotated, name)
		}
	}
	sort.Strings(rotated)
	for i := 0; i < len(rotated)-auditKeepRotated; i++ {
		_ = os.Remove(filepath.Join(dir, rotated[i]))
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		a.f = nil
		return
	}
	a.f = f
}

func (a *AuditLog) SetSink(fn func(AuditEntry)) {
	if a == nil || fn == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sink = fn
}

func (a *AuditLog) Log(event, ip, user, detail string) {
	if a == nil {
		return
	}
	e := AuditEntry{Time: time.Now(), Event: event, IP: ip, User: user, Detail: detail}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	data = append(data, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return
	}
	if st, err := a.f.Stat(); err == nil && st.Size()+int64(len(data)) > a.max {
		a.rotateLocked()
		if a.f == nil {
			return
		}
	}
	a.f.Write(data)
	if a.sink != nil {
		fn := a.sink
		go fn(e)
	}
}

func (a *AuditLog) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.f.Close()
}

func Recover(logger *log.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Printf("panic recuperado %s %s: %v", r.Method, r.URL.Path, rec)
					http.Error(w, "error interno", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func SecureHeaders(withCSP bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("X-DNS-Prefetch-Control", "off")
			proto := r.Header.Get("X-Forwarded-Proto")
			if r.TLS != nil || strings.EqualFold(proto, "https") {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			if withCSP {
				h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func BodyLimit(n int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

var unsafeMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

func CheckOrigin() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if unsafeMethods[r.Method] {
				o := r.Header.Get("Origin")
				if o != "" && o != "null" {
					u, err := url.Parse(o)
					if err != nil || !strings.EqualFold(u.Host, r.Host) {
						http.Error(w, "origen no permitido", http.StatusForbidden)
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

type cidrNet struct {
	ipnet *net.IPNet
}

func ParseCIDRList(list []string) ([]cidrNet, []string) {
	var nets []cidrNet
	var errs []string
	for _, c := range list {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			if ip := net.ParseIP(c); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				c = c + "/" + itoa(bits)
			} else {
				errs = append(errs, c)
				continue
			}
		}
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			errs = append(errs, c)
			continue
		}
		nets = append(nets, cidrNet{ipnet: ipnet})
	}
	return nets, errs
}

func itoa(i int) string {
	if i == 32 {
		return "32"
	}
	return "128"
}

func IPInNets(ipStr string, nets []cidrNet) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}
