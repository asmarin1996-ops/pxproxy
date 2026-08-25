package metrics

import (
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecordRequest(t *testing.T) {
	m := &Metrics{
		requestTotal:      make(map[string]*uint64),
		requestDurationNs: make(map[string]*uint64),
		requestCount:      make(map[string]*uint64),
		startedAt:         time.Now(),
	}

	for i := 0; i < 100; i++ {
		m.RecordRequest("GET", "/api/test", "ok", time.Duration(i)*time.Millisecond)
	}

	key := "GET /api/test"
	m.mu.RLock()
	total := *m.requestTotal[key]
	cnt := *m.requestCount[key]
	dur := *m.requestDurationNs[key]
	m.mu.RUnlock()

	if total != 100 {
		t.Fatalf("total: got %d, want 100", total)
	}
	if cnt != 100 {
		t.Fatalf("count: got %d, want 100", cnt)
	}
	if dur == 0 {
		t.Fatal("duration should be > 0")
	}
}

func TestRecordRequestConcurrent(t *testing.T) {
	m := &Metrics{
		requestTotal:      make(map[string]*uint64),
		requestDurationNs: make(map[string]*uint64),
		requestCount:      make(map[string]*uint64),
		startedAt:         time.Now(),
	}

	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				m.RecordRequest("POST", "/api/write", "ok", time.Millisecond)
			}
		}()
	}
	wg.Wait()

	key := "POST /api/write"
	m.mu.RLock()
	total := *m.requestTotal[key]
	m.mu.RUnlock()

	if total != 10000 {
		t.Fatalf("total: got %d, want 10000", total)
	}
}

func TestActiveConns(t *testing.T) {
	m := &Metrics{startedAt: time.Now()}
	m.IncActiveConns()
	m.IncActiveConns()
	if got := atomic.LoadInt64(&m.activeConns); got != 2 {
		t.Fatalf("active: got %d, want 2", got)
	}
	m.DecActiveConns()
	if got := atomic.LoadInt64(&m.activeConns); got != 1 {
		t.Fatalf("active: got %d, want 1", got)
	}
}

func TestMetricsHandler(t *testing.T) {
	m := Default
	m.RecordRequest("GET", "/api/health", "ok", 10*time.Millisecond)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "pxproxy_requests_total") {
		t.Fatal("missing pxproxy_requests_total")
	}
	if !strings.Contains(body, "pxproxy_uptime_seconds") {
		t.Fatal("missing pxproxy_uptime_seconds")
	}
	if !strings.Contains(body, "pxproxy_memory_alloc_bytes") {
		t.Fatal("missing pxproxy_memory_alloc_bytes")
	}
}

func TestNormalizeRoute(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/", "/"},
		{"/api", "/api"},
		{"/api/rules", "/api/rules"},
		{"/api/rules/123", "/api/rules/*"},
		{"/auth/login/local", "/auth/login/*"},
		{"/api/config/backup", "/api/config/*"},
	}
	for _, tt := range tests {
		got := NormalizeRoute(tt.in)
		if got != tt.want {
			t.Errorf("NormalizeRoute(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
