package auth

import (
	"testing"
	"time"
)

func TestTOTPCodeRFC6238Vectors(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, c := range cases {
		got, err := TOTPCode(secret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("TOTPCode(%d): %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("TOTPCode(t=%d) = %s; want %s", c.unix, got, c.want)
		}
	}
}

func TestTOTPCodeRotatesEveryStep(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	base := time.Unix(30*(1700000000/30), 0)
	a, _ := TOTPCode(secret, base)
	b, _ := TOTPCode(secret, base.Add(29*time.Second))
	c, _ := TOTPCode(secret, base.Add(31*time.Second))
	if a != b {
		t.Errorf("codigo cambio dentro de la ventana: %s vs %s", a, b)
	}
	if a == c {
		t.Errorf("codigo no roto entre ventanas: %s", a)
	}
}

func TestVerifyTOTPCodeRejectsBadFormat(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, code := range []string{"", "12345", "1234567", "abcdef", "12 456"} {
		if VerifyTOTPCode(secret, code) {
			t.Errorf("VerifyTOTPCode acepto codigo invalido %q", code)
		}
	}
	if VerifyTOTPCode("CORTA", "123456") {
		t.Error("VerifyTOTPCode acepto secreto corto")
	}
}

func TestVerifyTOTPCodeAcceptsCurrentCode(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code, err := TOTPCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyTOTPCode(secret, code) {
		t.Errorf("no verifico el codigo vigente %s", code)
	}
	prev, _ := TOTPCode(secret, now.Add(-totpStep))
	next, _ := TOTPCode(secret, now.Add(totpStep))
	if prev == next && prev != code && !VerifyTOTPCode(secret, prev) && !VerifyTOTPCode(secret, next) {
		t.Log("ventanas adyacentes distintas del actual; skew no comprobable en este instante")
	}
}

// TestVerifyTOTPCodeSkewWindow comprueba que el codigo se acepta dentro de la
// ventana de tolerancia de reloj (skew) definida por totpSkew, tanto pasada
// como futura, y que se rechaza fuera de ella. El uso de verifyTOTPCodeAt hace
// la prueba determinista.
func TestVerifyTOTPCodeSkewWindow(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	at := time.Unix(1700000000, 0)
	code, err := TOTPCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyTOTPCodeAt(secret, code, at) {
		t.Fatalf("deberia aceptar el codigo vigente en el instante dado")
	}
	for d := int64(1); d <= totpSkew; d++ {
		past, _ := TOTPCode(secret, at.Add(-time.Duration(d)*totpStep))
		future, _ := TOTPCode(secret, at.Add(time.Duration(d)*totpStep))
		if !verifyTOTPCodeAt(secret, past, at) {
			t.Errorf("deberia aceptar codigo %d pasos atras", d)
		}
		if !verifyTOTPCodeAt(secret, future, at) {
			t.Errorf("deberia aceptar codigo %d pasos adelante", d)
		}
	}
	// Fuera de la ventana de skew debe rechazarse (si el codigo no coincide por
	// casualidad con alguna ventana).
	out, _ := TOTPCode(secret, at.Add(-time.Duration(totpSkew+2)*totpStep))
	if verifyTOTPCodeAt(secret, out, at) {
		t.Errorf("acepto codigo fuera de la ventana de skew (2 pasos extra)")
	}
}

func TestNormalizeSecretRejectsInvalidBase32(t *testing.T) {
	if _, err := normalizeSecret("CORTONOVALIDO"); err == nil {
		t.Errorf("normalizeSecret deberia rechazar un secreto que no es base32 valido")
	}
	if _, err := normalizeSecret("0-0-0-0-0-0-0-0-0-0-0"); err == nil {
		t.Errorf("normalizeSecret deberia rechazar caracteres no base32")
	}
}

func TestProvisionURI(t *testing.T) {
	uri := ProvisionURI("PxProxy", "a@b.com", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	for _, part := range []string{"otpauth://totp/", "secret=GEZDG", "issuer=PxProxy", "digits=6", "period=30"} {
		if !contains(uri, part) {
			t.Errorf("URI sin %q: %s", part, uri)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
