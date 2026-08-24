package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLimiterLockAndReset(t *testing.T) {
	l := NewLimiter(3, time.Minute, time.Minute)
	for i := 0; i < 2; i++ {
		if locked := l.Fail("k"); locked {
			t.Fatal("bloqueo prematuro")
		}
	}
	if ok, _ := l.Allowed("k"); !ok {
		t.Fatal("deberia permitir antes del limite")
	}
	if !l.Fail("k") {
		t.Fatal("el fallo numero max deberia bloquear")
	}
	if ok, until := l.Allowed("k"); ok || until.IsZero() {
		t.Fatal("la clave bloqueada no debe pasar")
	}
	l.Reset("k")
	if ok, _ := l.Allowed("k"); !ok {
		t.Fatal("Reset no desbloqueo")
	}
}

func TestLimiterSnapshotRestore(t *testing.T) {
	l1 := NewLimiter(3, time.Hour, time.Hour)
	l1.Fail("ip|1.2.3.4")
	l1.Fail("ip|1.2.3.4")
	l1.Fail("user|ana")
	snap := l1.Snapshot()
	if len(snap.Entries) != 2 {
		t.Fatalf("snapshot con %d entradas; want 2", len(snap.Entries))
	}
	l2 := NewLimiter(3, time.Hour, time.Hour)
	l2.Restore(snap)
	if got := len(l2.Snapshot().Entries); got != 2 {
		t.Fatalf("tras restaurar hay %d entradas; want 2", got)
	}
	if !l2.Fail("ip|1.2.3.4") {
		t.Fatal("tras restaurar 2 fallos, el tercero debia bloquear")
	}
}

func TestAuditRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := OpenAudit(path, 400)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for i := 0; i < 40; i++ {
		a.Log("login_failed", "10.0.0.9", "usuario bastante largo para ocupar", "detalle adicional del evento")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	rotated := 0
	currentSize := int64(0)
	for _, e := range ents {
		name := e.Name()
		if name == "audit.log" {
			info, _ := e.Info()
			currentSize = info.Size()
		} else if strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".log") {
			rotated++
		}
	}
	if rotated == 0 {
		t.Fatal("no hubo rotacion con umbral pequeno")
	}
	if currentSize > 800 {
		t.Errorf("audit.log actual crecio sin control: %d bytes", currentSize)
	}
}
