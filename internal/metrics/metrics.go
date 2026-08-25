package metrics

import (
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	requestTotal      map[string]*uint64
	requestDurationNs map[string]*uint64
	requestCount      map[string]*uint64
	activeConns       int64
	backendOk         int64
	backendVersion    string
	mu                sync.RWMutex
	startedAt         time.Time
}

var Default = &Metrics{
	requestTotal:      make(map[string]*uint64),
	requestDurationNs: make(map[string]*uint64),
	requestCount:      make(map[string]*uint64),
	startedAt:         time.Now(),
}

func (m *Metrics) RecordRequest(method, path, status string, duration time.Duration) {
	key := method + " " + path
	n := duration.Nanoseconds()

	m.mu.RLock()
	totalPtr, ok1 := m.requestTotal[key]
	durPtr := m.requestDurationNs[key]
	cntPtr := m.requestCount[key]
	m.mu.RUnlock()

	if !ok1 {
		m.mu.Lock()
		if _, ok := m.requestTotal[key]; !ok {
			var t, d, c uint64
			m.requestTotal[key] = &t
			m.requestDurationNs[key] = &d
			m.requestCount[key] = &c
		}
		totalPtr = m.requestTotal[key]
		durPtr = m.requestDurationNs[key]
		cntPtr = m.requestCount[key]
		m.mu.Unlock()
	}

	atomic.AddUint64(totalPtr, 1)
	atomic.AddUint64(durPtr, uint64(n))
	atomic.AddUint64(cntPtr, 1)
}

func (m *Metrics) IncActiveConns()   { atomic.AddInt64(&m.activeConns, 1) }
func (m *Metrics) DecActiveConns()   { atomic.AddInt64(&m.activeConns, -1) }
func (m *Metrics) SetBackendOk(v bool) {
	if v {
		atomic.StoreInt64(&m.backendOk, 1)
	} else {
		atomic.StoreInt64(&m.backendOk, 0)
	}
}
func (m *Metrics) SetBackendVersion(v string) { m.mu.Lock(); m.backendVersion = v; m.mu.Unlock() }

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var sb strings.Builder

		sb.WriteString("# HELP pxproxy_requests_total Total de peticiones por ruta.\n")
		sb.WriteString("# TYPE pxproxy_requests_total counter\n")
		m.mu.RLock()
		for key, ptr := range m.requestTotal {
			val := atomic.LoadUint64(ptr)
			sb.WriteString("pxproxy_requests_total{route=\"")
			sb.WriteString(escapeMetric(key))
			sb.WriteString("\"} ")
			sb.WriteString(itoa(val))
			sb.WriteString("\n")
		}

		sb.WriteString("# HELP pxproxy_request_duration_seconds Duracion promedio por ruta.\n")
		sb.WriteString("# TYPE pxproxy_request_duration_seconds gauge\n")
		for key, durPtr := range m.requestDurationNs {
			cntPtr := m.requestCount[key]
			cnt := atomic.LoadUint64(cntPtr)
			if cnt == 0 {
				continue
			}
			dur := atomic.LoadUint64(durPtr)
			avgSec := float64(dur) / float64(cnt) / 1e9
			sb.WriteString("pxproxy_request_duration_seconds{route=\"")
			sb.WriteString(escapeMetric(key))
			sb.WriteString("\"} ")
			sb.WriteString(ftoa(avgSec))
			sb.WriteString("\n")
		}
		m.mu.RUnlock()

		active := atomic.LoadInt64(&m.activeConns)
		sb.WriteString("# HELP pxproxy_active_connections Conexiones activas.\n")
		sb.WriteString("# TYPE pxproxy_active_connections gauge\n")
		sb.WriteString("pxproxy_active_connections ")
		sb.WriteString(itoa(uint64(active)))
		sb.WriteString("\n")

		backend := atomic.LoadInt64(&m.backendOk)
		sb.WriteString("# HELP pxproxy_storage_ok Estado del backend PostgreSQL (1=ok, 0=down).\n")
		sb.WriteString("# TYPE pxproxy_storage_ok gauge\n")
		sb.WriteString("pxproxy_storage_ok ")
		if backend > 0 {
			sb.WriteString("1\n")
		} else {
			sb.WriteString("0\n")
		}

		m.mu.RLock()
		version := m.backendVersion
		m.mu.RUnlock()
		if version != "" {
			sb.WriteString("# HELP pxproxy_storage_version_info Metadata del backend.\n")
			sb.WriteString("# TYPE pxproxy_storage_version_info gauge\n")
			sb.WriteString("pxproxy_storage_version_info{version=\"")
			sb.WriteString(escapeMetric(version))
			sb.WriteString("\"} 1\n")
		}

		uptime := time.Since(m.startedAt).Seconds()
		sb.WriteString("# HELP pxproxy_uptime_seconds Tiempo de actividad.\n")
		sb.WriteString("# TYPE pxproxy_uptime_seconds gauge\n")
		sb.WriteString("pxproxy_uptime_seconds ")
		sb.WriteString(ftoa(uptime))
		sb.WriteString("\n")

		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		sb.WriteString("# HELP pxproxy_memory_alloc_bytes Memoria allocada.\n")
		sb.WriteString("# TYPE pxproxy_memory_alloc_bytes gauge\n")
		sb.WriteString("pxproxy_memory_alloc_bytes ")
		sb.WriteString(itoa(mem.Alloc))
		sb.WriteString("\n")
		sb.WriteString("# HELP pxproxy_memory_sys_bytes Memoria sistema.\n")
		sb.WriteString("# TYPE pxproxy_memory_sys_bytes gauge\n")
		sb.WriteString("pxproxy_memory_sys_bytes ")
		sb.WriteString(itoa(mem.Sys))
		sb.WriteString("\n")
		sb.WriteString("# HELP pxproxy_go_goroutines Goroutines activas.\n")
		sb.WriteString("# TYPE pxproxy_go_goroutines gauge\n")
		sb.WriteString("pxproxy_go_goroutines ")
		sb.WriteString(itoa(uint64(runtime.NumGoroutine())))
		sb.WriteString("\n")

		w.Write([]byte(sb.String()))
	})
}

func escapeMetric(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func ftoa(f float64) string {
	if f == 0 {
		return "0"
	}
	const prec = 6
	buf := make([]byte, 0, prec+3)
	if f < 0 {
		buf = append(buf, '-')
		f = -f
	}

	x := uint64(f)
	frac := f - float64(x)
	var intBuf [20]byte
	j := len(intBuf)
	if x == 0 {
		j--
		intBuf[j] = '0'
	} else {
		for x > 0 {
			j--
			intBuf[j] = byte('0' + x%10)
			x /= 10
		}
	}
	buf = append(buf, intBuf[j:]...)

	if frac > 0 {
		buf = append(buf, '.')
		for i := 0; i < prec; i++ {
			frac *= 10
			d := uint64(frac)
			buf = append(buf, byte('0'+d))
			frac -= float64(d)
		}
		for len(buf) > 0 && buf[len(buf)-1] == '0' {
			buf = buf[:len(buf)-1]
		}
	}
	return string(buf)
}

func NormalizeRoute(path string) string {
	if path == "" {
		return "/"
	}
	parts := strings.Split(path, "/")
	if len(parts) <= 3 {
		return path
	}
	return strings.Join(parts[:3], "/") + "/*"
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Default.IncActiveConns()
		defer Default.DecActiveConns()
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		status := "ok"
		if sw.status >= 400 {
			status = "error"
		}
		Default.RecordRequest(r.Method, NormalizeRoute(r.URL.Path), status, time.Since(start))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}
