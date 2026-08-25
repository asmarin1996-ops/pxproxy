package health

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"sync"
	"time"
)

type Status struct {
	Target         string    `json:"target"`
	Healthy        bool      `json:"healthy"`
	ConsecFails    int       `json:"consec_fails"`
	LastCheck      time.Time `json:"last_check"`
	LastErr        string    `json:"last_err,omitempty"`
	CheckCount     int64     `json:"check_count"`
	FailCount      int64     `json:"fail_count"`
	LastSuccessMs  int64     `json:"last_success_ms,omitempty"`
}

type Checker struct {
	mu       sync.RWMutex
	targets  map[string]*Status
	healthy  map[string]bool
	interval time.Duration
	timeout  time.Duration
	failures int
	logger   *log.Logger
	client   *http.Client
	cancel   context.CancelFunc
	onChange func(target string, healthy bool)
}

func New(interval, timeout time.Duration, failures int, logger *log.Logger) *Checker {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if failures <= 0 {
		failures = 3
	}
	return &Checker{
		targets:  make(map[string]*Status),
		healthy:  make(map[string]bool),
		interval: interval,
		timeout:  timeout,
		failures: failures,
		logger:   logger,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
			},
		},
	}
}

func (c *Checker) Start(ctx context.Context) {
	ctx, c.cancel = context.WithCancel(ctx)
	go c.loop(ctx)
}

func (c *Checker) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}

func (c *Checker) SetOnChange(fn func(target string, healthy bool)) {
	c.onChange = fn
}

func (c *Checker) SetTargets(targets []string) {
	c.mu.Lock()
	next := make(map[string]*Status, len(targets))
	nextHealthy := make(map[string]bool, len(targets))
	for _, t := range targets {
		if t == "" {
			continue
		}
		if old, ok := c.targets[t]; ok {
			next[t] = old
			nextHealthy[t] = c.healthy[t]
		} else {
			next[t] = &Status{Target: t, Healthy: true}
			nextHealthy[t] = true
		}
	}
	c.targets = next
	c.healthy = nextHealthy
	c.mu.Unlock()
}

func (c *Checker) IsHealthy(target string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h, ok := c.healthy[target]
	if !ok {
		return true
	}
	return h
}

func (c *Checker) Snapshot() []Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Status, 0, len(c.targets))
	for _, s := range c.targets {
		cp := *s
		cp.Healthy = c.healthy[s.Target]
		out = append(out, cp)
	}
	return out
}

func (c *Checker) loop(ctx context.Context) {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.probe()
		}
	}
}

func (c *Checker) probe() {
	c.mu.RLock()
	targets := make([]string, 0, len(c.targets))
	for t := range c.targets {
		targets = append(targets, t)
	}
	c.mu.RUnlock()

	for _, t := range targets {
		c.checkOne(t)
	}
}

func (c *Checker) checkOne(target string) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		c.record(target, false, err.Error())
		return
	}
	req.Header.Set("User-Agent", "pxproxy-healthcheck/1.0")
	resp, err := c.client.Do(req)
	if err != nil {
		c.record(target, false, err.Error())
		return
	}
	resp.Body.Close()
	ok := resp.StatusCode < 500
	msg := ""
	if !ok {
		msg = "status " + http.StatusText(resp.StatusCode)
	}
	c.record(target, ok, msg)
}

func (c *Checker) record(target string, ok bool, errMsg string) {
	c.mu.Lock()
	s, exists := c.targets[target]
	if !exists {
		c.mu.Unlock()
		return
	}
	prevHealthy, hadPrev := c.healthy[target]
	s.CheckCount++
	s.LastCheck = time.Now()
	if ok {
		s.ConsecFails = 0
		s.LastErr = ""
		s.LastSuccessMs = time.Now().UnixMilli()
		c.healthy[target] = true
	} else {
		s.ConsecFails++
		s.FailCount++
		s.LastErr = errMsg
		if s.ConsecFails >= c.failures {
			c.healthy[target] = false
			if s.ConsecFails == c.failures {
				c.logger.Printf("upstream marcado DOWN: %s (fallos consecutivos: %d)", target, s.ConsecFails)
			}
		}
	}
	stateChanged := !hadPrev || prevHealthy != c.healthy[target]
	nowHealthy := c.healthy[target]
	c.mu.Unlock()
	if c.onChange != nil && stateChanged {
		c.onChange(target, nowHealthy)
	}
}

func (c *Checker) MarkAllHealthy() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for t := range c.healthy {
		c.healthy[t] = true
		if s, ok := c.targets[t]; ok {
			s.ConsecFails = 0
			s.LastErr = ""
		}
	}
}
