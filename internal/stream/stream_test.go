package stream

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"proxy/internal/config"
)

func TestRuleKey(t *testing.T) {
	if got := ruleKey(config.StreamRule{Listen: "  0.0.0.0:993  "}); got != "0.0.0.0:993" {
		t.Errorf("ruleKey = %q", got)
	}
}

func TestValidateAddress(t *testing.T) {
	if err := ValidateAddress("0.0.0.0:993"); err != nil {
		t.Errorf("valida debe pasar: %v", err)
	}
	if err := ValidateAddress("172.22.33.17:143"); err != nil {
		t.Errorf("target valido fallo: %v", err)
	}
	if err := ValidateAddress("993"); err == nil {
		t.Error("debe fallar sin host:puerto")
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestManagerPlainRelay(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(cc net.Conn) {
				defer cc.Close()
				_, _ = io.Copy(cc, cc)
			}(c)
		}
	}()

	proxyAddr := freePort(t)
	mgr := New(nil, nil)
	mgr.Apply([]config.StreamRule{{
		Listen:  proxyAddr,
		Target:  backend.Addr().String(),
		Enabled: true,
	}})
	time.Sleep(50 * time.Millisecond)

	c, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		mgr.Close()
		t.Fatalf("dial al proxy: %v", err)
	}
	defer c.Close()
	payload := "hola stream"
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), payload) {
		t.Errorf("eco inesperado: %q, err=%v", string(buf[:n]), err)
	}
	mgr.Close()
}