package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const totpStep = 30 * time.Second
const totpDigits = 6
const totpSkew = 1

func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

func normalizeSecret(secret string) ([]byte, error) {
	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(secret, " ", ""), "-", ""))
	if len(clean) < 16 {
		return nil, errors.New("secreto TOTP demasiado corto")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
}

func hotp(key []byte, counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	m := hmac.New(sha1.New, key)
	m.Write(buf)
	sum := m.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	s := fmt.Sprintf("%0*d", totpDigits, code%mod)
	return s
}

func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := normalizeSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix() / int64(totpStep/time.Second))
	return hotp(key, counter), nil
}

func VerifyTOTPCode(secret, code string) bool {
	key, err := normalizeSecret(secret)
	if err != nil {
		return false
	}
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	now := uint64(time.Now().Unix() / int64(totpStep/time.Second))
	valid := false
	for d := int64(0); d <= totpSkew; d++ {
		for _, c := range []uint64{now + uint64(d), now - uint64(d)} {
			expected := hotp(key, c)
			if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
				valid = true
			}
		}
	}
	return valid
}

func ProvisionURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s?%s", label, q.Encode())
}
