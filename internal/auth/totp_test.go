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
