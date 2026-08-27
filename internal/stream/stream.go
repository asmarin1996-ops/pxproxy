package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"proxy/internal/config"
)

// Status describe una regla de stream y si el listener esta activo.
type Status struct {
	Listen  string `json:"listen"`
	Target  string `json:"target"`
	TLS     bool   `json:"tls"`
	SNIHost string `json:"sni_host"`
	Enabled bool   `json:"enabled"`
	Running bool   `json:"running"`
	Error   string `json:"error,omitempty"`
}

// Manager reconcilia los listeners TCP (stream proxy). Con TLS=true termina
// el TLS entrante: el certificado se resuelve por SNI a traves de getCert,
// que consulta primero los certificados propios y luego ACME.
type Manager struct {
	logger *log.Logger
	getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	mu       sync.Mutex
	running  map[string]*listener
	lastErrs map[string]string
}

type listener struct {
	rule   config.StreamRule
	ln     net.Listener
	cancel context.CancelFunc
	conns  sync.WaitGroup
	mu     sync.Mutex
	active map[net.Conn]struct{}
}

func New(logger *log.Logger, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *Manager {
	if logger == nil {
		logger = log.Default()
	}
	return &Manager{logger: logger, getCert: getCert, running: map[string]*listener{}, lastErrs: map[string]string{}}
}

func ruleKey(r config.StreamRule) string {
	return strings.ToLower(strings.TrimSpace(r.Listen))
}

// Apply arranca, mantiene y detiene los listeners para que coincidan con las
// reglas habilitadas indicadas. Es idempotente y seguro de llamar en recargas.
func (m *Manager) Apply(rules []config.StreamRule) {
	wanted := map[string]config.StreamRule{}
	for _, r := range rules {
		listen := strings.TrimSpace(r.Listen)
		target := strings.TrimSpace(r.Target)
		if !r.Enabled || listen == "" || target == "" {
			continue
		}
		wanted[ruleKey(r)] = r
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for k, l := range m.running {
		if _, ok := wanted[k]; ok {
			continue
		}
		l.stop()
		delete(m.running, k)
		m.logger.Printf("stream %s detenido", k)
	}
	for k, r := range wanted {
		if _, ok := m.running[k]; ok {
			continue
		}
		l := &listener{rule: r}
		if err := m.startLocked(l); err != nil {
			m.lastErrs[k] = err.Error()
			m.logger.Printf("stream %s no pudo iniciar: %v", k, err)
			continue
		}
		m.running[k] = l
		delete(m.lastErrs, k)
		m.logger.Printf("stream %s -> %s (tls=%v)", r.Listen, r.Target, r.TLS)
	}
}

func (m *Manager) startLocked(l *listener) error {
	ln, err := net.Listen("tcp", l.rule.Listen)
	if err != nil {
		return err
	}
	if l.rule.TLS {
		if m.getCert == nil {
			_ = ln.Close()
			return errors.New("no hay resolver de certificados para TLS")
		}
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: m.getCert}
		ln = tls.NewListener(ln, tlsCfg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	l.ln = ln
	l.cancel = cancel
	l.active = map[net.Conn]struct{}{}
	go m.acceptLoop(ctx, l)
	return nil
}

func (m *Manager) acceptLoop(ctx context.Context, l *listener) {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			m.logger.Printf("stream %s error de aceptacion: %v", l.rule.Listen, err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		l.conns.Add(1)
		l.mu.Lock()
		l.active[conn] = struct{}{}
		l.mu.Unlock()
		go func(c net.Conn) {
			defer l.conns.Done()
			defer func() {
				l.mu.Lock()
				delete(l.active, c)
				l.mu.Unlock()
			}()
			m.handle(ctx, l.rule, c)
		}(conn)
	}
}

func (m *Manager) handle(ctx context.Context, rule config.StreamRule, conn net.Conn) {
	defer conn.Close()

	if tc, ok := conn.(*tls.Conn); ok {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.Handshake(); err != nil {
			m.logger.Printf("stream %s handshake TLS fallido (%v)", rule.Listen, err)
			return
		}
		_ = conn.SetDeadline(time.Time{})
	}

	target := strings.TrimSpace(rule.Target)
	up, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		m.logger.Printf("stream %s -> %s conexion fallida: %v", rule.Listen, target, err)
		return
	}
	defer up.Close()

	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
	}
	if tcp, ok := up.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
	}

	idle := time.Duration(rule.TimeoutSec) * time.Second
	if idle > 0 {
		_ = conn.SetDeadline(time.Now().Add(idle))
		_ = up.SetDeadline(time.Now().Add(idle))
		go watchIdle(ctx, conn, up, idle)
	}

	done := make(chan struct{}, 2)
	go relay(conn, up, done)
	go relay(up, conn, done)
	<-done
}

func watchIdle(ctx context.Context, a, b net.Conn, idle time.Duration) {
	t := time.NewTicker(idle / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = a.SetDeadline(time.Now().Add(idle))
			_ = b.SetDeadline(time.Now().Add(idle))
		}
	}
}

func relay(dst, src net.Conn, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	done <- struct{}{}
}

func (l *listener) stop() {
	if l.cancel != nil {
		l.cancel()
	}
	if l.ln != nil {
		_ = l.ln.Close()
	}
	l.mu.Lock()
	for c := range l.active {
		_ = c.Close()
	}
	l.mu.Unlock()
	l.conns.Wait()
}

// Close detiene todos los listeners.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, l := range m.running {
		l.stop()
		delete(m.running, k)
		m.logger.Printf("stream %s detenido (apagado)", k)
	}
}

// Status devuelve el estado de las reglas configuradas y sus listeners.
func (m *Manager) Status(rules []config.StreamRule) []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(rules))
	for _, r := range rules {
		st := Status{
			Listen:  strings.TrimSpace(r.Listen),
			Target:  strings.TrimSpace(r.Target),
			TLS:     r.TLS,
			SNIHost: r.SNIHost,
			Enabled: r.Enabled,
		}
		if !st.Enabled {
			out = append(out, st)
			continue
		}
		if _, ok := m.running[ruleKey(r)]; ok {
			st.Running = true
		} else {
			st.Error = m.lastErrs[ruleKey(r)]
		}
		out = append(out, st)
	}
	return out
}

// ValidateAddress valida un par host:puerto para Listen/Target.
func ValidateAddress(addr string) error {
	a := strings.TrimSpace(addr)
	if a == "" {
		return fmt.Errorf("direccion vacia")
	}
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return fmt.Errorf("forma esperada host:puerto (%q)", a)
	}
	if host == "" || port == "" {
		return fmt.Errorf("host y puerto requeridos")
	}
	return nil
}