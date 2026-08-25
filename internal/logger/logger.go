package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error", "err":
		return LevelError
	default:
		return LevelInfo
	}
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}

type Entry struct {
	Timestamp string `json:"ts"`
	Level     string `json:"level"`
	Message   string `json:"msg"`
	Component string `json:"component,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

type Logger struct {
	out       io.Writer
	level     Level
	component string
	mu        sync.Mutex
}

func New(out io.Writer, level Level, component string) *Logger {
	return &Logger{out: out, level: level, component: component}
}

func (l *Logger) log(level Level, component, requestID, msg string) {
	if level < l.level {
		return
	}
	e := Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level.String(),
		Message:   msg,
		Component: component,
		RequestID: requestID,
	}
	data, _ := json.Marshal(e)
	l.mu.Lock()
	l.out.Write(data)
	l.out.Write([]byte("\n"))
	l.mu.Unlock()
}

func (l *Logger) Debugf(component, requestID, format string, args ...any) {
	l.log(LevelDebug, component, requestID, fmt.Sprintf(format, args...))
}

func (l *Logger) Infof(component, requestID, format string, args ...any) {
	l.log(LevelInfo, component, requestID, fmt.Sprintf(format, args...))
}

func (l *Logger) Warnf(component, requestID, format string, args ...any) {
	l.log(LevelWarn, component, requestID, fmt.Sprintf(format, args...))
}

func (l *Logger) Errorf(component, requestID, format string, args ...any) {
	l.log(LevelError, component, requestID, fmt.Sprintf(format, args...))
}

func (l *Logger) Printf(format string, args ...any) {
	l.log(LevelInfo, l.component, "", fmt.Sprintf(format, args...))
}

func (l *Logger) Println(v ...any) {
	l.log(LevelInfo, l.component, "", fmt.Sprint(v...))
}

func (l *Logger) Fatalf(format string, args ...any) {
	l.log(LevelError, l.component, "", fmt.Sprintf(format, args...))
	os.Exit(1)
}

func (l *Logger) Fatal(v ...any) {
	l.log(LevelError, l.component, "", fmt.Sprint(v...))
	os.Exit(1)
}

func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	l.level = level
	l.mu.Unlock()
}

func (l *Logger) WithComponent(c string) *Logger {
	return &Logger{out: l.out, level: l.level, component: c}
}

func (l *Logger) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.out.Write(p)
}

func StdLogger(l *Logger) *log.Logger {
	return log.New(l, "", 0)
}
