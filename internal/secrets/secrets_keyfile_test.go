//go:build !windows

package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyfileRoundTrip(t *testing.T) {
	UseKeyFile(filepath.Join(t.TempDir(), "secrets.key"))
	orig := "secreto-para-ubuntu-server-1234567890"
	sealed := Seal(orig)
	if sealed == orig || !IsProtected(sealed) {
		t.Fatal("Seal no protegio el valor con keyfile")
	}
	if !strings.HasPrefix(sealed, encPrefix) {
		t.Fatalf("prefijo = %q; want enc1:", sealed[:5])
	}
	if got := Open(sealed); got != orig {
		t.Fatalf("Open = %q; want %q", got, orig)
	}
}

func TestKeyfileCreatedWithContent(t *testing.T) {
	dir := t.TempDir()
	kp := filepath.Join(dir, "secrets.key")
	UseKeyFile(kp)
	Seal("algo")
	k1, err := os.ReadFile(kp)
	if err != nil || len(k1) != 32 {
		t.Fatalf("keyfile no creado/valido: len=%d err=%v", len(k1), err)
	}
}
