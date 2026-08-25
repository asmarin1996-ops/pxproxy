package health

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestIsHealthyDefaultTrue(t *testing.T) {
	c := New(time.Hour, time.Second, 3, log.New(os.Stderr, "", 0))
	if !c.IsHealthy("unknown") {
		t.Fatal("unknown target should default to healthy")
	}
}

func TestSetTargets(t *testing.T) {
	c := New(time.Hour, time.Second, 3, log.New(os.Stderr, "", 0))
	c.SetTargets([]string{"http://a.local", "http://b.local"})
	if !c.IsHealthy("http://a.local") {
		t.Fatal("new target should be healthy by default")
	}
	snap := c.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(snap))
	}
}

func TestUpstreamHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(time.Hour, 2*time.Second, 3, log.New(os.Stderr, "", 0))
	c.SetTargets([]string{srv.URL})

	c.checkOne(srv.URL)
	if !c.IsHealthy(srv.URL) {
		t.Fatal("upstream should be healthy after successful check")
	}
}

func TestUpstreamDown(t *testing.T) {
	fails := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fails++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(time.Hour, 2*time.Second, 2, log.New(os.Stderr, "", 0))
	c.SetTargets([]string{srv.URL})

	c.checkOne(srv.URL)
	if !c.IsHealthy(srv.URL) {
		t.Fatal("should still be healthy after 1 failure (threshold=2)")
	}

	c.checkOne(srv.URL)
	if c.IsHealthy(srv.URL) {
		t.Fatal("should be down after 2 consecutive failures")
	}
}

func TestUpstreamDownThenRecovers(t *testing.T) {
	ok := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	c := New(time.Hour, 2*time.Second, 2, log.New(os.Stderr, "", 0))
	c.SetTargets([]string{srv.URL})

	ok = false
	c.checkOne(srv.URL)
	c.checkOne(srv.URL)
	if c.IsHealthy(srv.URL) {
		t.Fatal("should be down")
	}

	ok = true
	c.checkOne(srv.URL)
	if !c.IsHealthy(srv.URL) {
		t.Fatal("should recover after single success")
	}
}

func TestMarkAllHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(time.Hour, 2*time.Second, 2, log.New(os.Stderr, "", 0))
	c.SetTargets([]string{srv.URL})

	c.checkOne(srv.URL)
	c.checkOne(srv.URL)
	if c.IsHealthy(srv.URL) {
		t.Fatal("should be down")
	}

	c.MarkAllHealthy()
	if !c.IsHealthy(srv.URL) {
		t.Fatal("should be healthy after MarkAllHealthy")
	}
}

func TestOnChangeCallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(time.Hour, 2*time.Second, 2, log.New(os.Stderr, "", 0))
	c.SetTargets([]string{srv.URL})

	var changed string
	var changedHealthy bool
	c.SetOnChange(func(target string, healthy bool) {
		changed = target
		changedHealthy = healthy
	})

	c.checkOne(srv.URL)
	c.checkOne(srv.URL)
	if changed != srv.URL || changedHealthy {
		t.Fatalf("expected callback with %s false, got %s %v", srv.URL, changed, changedHealthy)
	}
}

func TestConcurrency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(time.Hour, 2*time.Second, 3, log.New(os.Stderr, "", 0))
	c.SetTargets([]string{srv.URL})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			c.IsHealthy(srv.URL)
			c.Snapshot()
		}
		close(done)
	}()
	for i := 0; i < 100; i++ {
		c.checkOne(srv.URL)
	}
	<-done
}
