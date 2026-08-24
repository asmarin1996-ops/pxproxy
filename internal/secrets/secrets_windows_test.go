//go:build windows

package secrets

import "testing"

func TestSealOpenRoundTrip(t *testing.T) {
	orig := "un-secreto-muy-largo-para-probar-DPAPI-1234567890"
	sealed := Seal(orig)
	if sealed == orig {
		t.Fatal("Seal no cifro el valor")
	}
	if !IsProtected(sealed) {
		t.Fatal("el valor sellado no lleva el prefijo dpapi1:")
	}
	got := Open(sealed)
	if got != orig {
		t.Fatalf("Open = %q; want %q", got, orig)
	}
}

func TestSealIdempotentAndPassthrough(t *testing.T) {
	sealed := Seal("abc")
	if again := Seal(sealed); again != sealed {
		t.Error("Seal no es idempotente sobre valores ya sellados")
	}
	if Open("texto-normal") != "texto-normal" {
		t.Error("Open debe dejar pasar texto sin prefijo")
	}
	if Seal("") != "" {
		t.Error("Seal de cadena vacia debe devolver cadena vacia")
	}
}
