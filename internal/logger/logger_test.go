package logger

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestLoggerJSON(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelInfo, "test")

	l.Printf("arrancando version %s", "1.0")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("json parse: %v", err)
	}
	if e.Timestamp == "" {
		t.Fatal("missing timestamp")
	}
	if e.Level != "info" {
		t.Fatalf("level: got %q, want info", e.Level)
	}
	if e.Component != "test" {
		t.Fatalf("component: got %q, want test", e.Component)
	}
	if !strings.Contains(e.Message, "arrancando") {
		t.Fatalf("message: %q", e.Message)
	}
}

func TestLoggerLevel(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelWarn, "test")

	l.Debugf("test", "", "debug msg")
	if buf.Len() > 0 {
		t.Fatal("debug should not appear at warn level")
	}

	l.Infof("test", "", "info msg")
	if buf.Len() > 0 {
		t.Fatal("info should not appear at warn level")
	}

	l.Warnf("test", "", "warn msg")
	if buf.Len() == 0 {
		t.Fatal("warn should appear at warn level")
	}

	buf.Reset()
	l.Errorf("test", "", "error msg")
	if buf.Len() == 0 {
		t.Fatal("error should appear at warn level")
	}
}

func TestLoggerRequestID(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelDebug, "")

	l.Infof("http", "req-123", "peticion procesada")

	var e Entry
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &e); err != nil {
		t.Fatalf("json: %v", err)
	}
	if e.RequestID != "req-123" {
		t.Fatalf("request_id: got %q, want req-123", e.RequestID)
	}
	if e.Component != "http" {
		t.Fatalf("component: got %q, want http", e.Component)
	}
}

func TestLoggerWithComponent(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelDebug, "root")
	child := l.WithComponent("child")

	child.Printf("mensaje")

	var e Entry
	json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &e)
	if e.Component != "child" {
		t.Fatalf("component: got %q, want child", e.Component)
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct{ s string; l Level }{
		{"debug", LevelDebug},
		{"INFO", LevelInfo},
		{"warn", LevelWarn},
		{"warning", LevelWarn},
		{"error", LevelError},
		{"unknown", LevelInfo},
		{"", LevelInfo},
	}
	for _, tt := range tests {
		got := ParseLevel(tt.s)
		if got != tt.l {
			t.Errorf("ParseLevel(%q) = %d, want %d", tt.s, got, tt.l)
		}
	}
}
