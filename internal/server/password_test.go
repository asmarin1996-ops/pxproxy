package server

import "testing"

func TestValidatePasswordStrengthAcceptsStrong(t *testing.T) {
	for _, pw := range []string{
		"Correcaminos#2026x",
		"Tr0n-y-P4lomita-Larga",
		"!Segura-Para-El-Panel-99",
	} {
		if msg := validatePasswordStrength(pw); msg != "" {
			t.Errorf("rechazo contrasena fuerte %q: %s", pw, msg)
		}
	}
}

func TestValidatePasswordStrengthRejectsWeak(t *testing.T) {
	for _, pw := range []string{
		"corta1!",
		"solominusculaslargas",
		"SOLOMAYUSCULASLARGAS",
		"123456789012345",
		"!!!!!!!!!!!!!!!!",
	} {
		if msg := validatePasswordStrength(pw); msg == "" {
			t.Errorf("acepto contrasena debil %q", pw)
		}
	}
}

func TestValidatePasswordStrengthLeetspeak(t *testing.T) {
	for _, pw := range []string{
		"Adm1n1str4d0r",  // administrador sin simbolos ni mayuscula real tras normalizar? conserva A
		"S3cur3P4ssw0rd", // securepassword leet, sin simbolo
	} {
		if msg := validatePasswordStrength(pw); msg == "" {
			t.Errorf("evasion leetspeak aceptada: %q", pw)
		}
	}
}
