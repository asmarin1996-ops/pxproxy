package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"sync"
)

const dpapiPrefix = "dpapi1:"
const encPrefix = "enc1:"

var (
	mu      sync.RWMutex
	keyPath string
)

func UseKeyFile(path string) {
	mu.Lock()
	defer mu.Unlock()
	keyPath = path
}

func IsProtected(s string) bool {
	return strings.HasPrefix(s, dpapiPrefix) || strings.HasPrefix(s, encPrefix)
}

func Seal(s string) string {
	if s == "" || IsProtected(s) {
		return s
	}
	if supported {
		if blob, err := dpapiSeal([]byte(s)); err == nil {
			return dpapiPrefix + base64.StdEncoding.EncodeToString(blob)
		}
	}
	if blob, err := sealKeyfile([]byte(s)); err == nil {
		return encPrefix + base64.StdEncoding.EncodeToString(blob)
	}
	return s
}

func Open(s string) string {
	switch {
	case strings.HasPrefix(s, dpapiPrefix):
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, dpapiPrefix))
		if err != nil {
			return s
		}
		b, err := dpapiOpen(raw)
		if err != nil {
			return s
		}
		return string(b)
	case strings.HasPrefix(s, encPrefix):
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, encPrefix))
		if err != nil {
			return s
		}
		b, err := openKeyfile(raw)
		if err != nil {
			return s
		}
		return string(b)
	}
	return s
}

func loadKey() ([]byte, error) {
	mu.RLock()
	p := keyPath
	mu.RUnlock()
	if p == "" {
		return nil, errors.New("secrets: sin archivo de claves configurado")
	}
	if k, err := os.ReadFile(p); err == nil && len(k) == 32 {
		return k, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, k, 0600); err != nil {
		return nil, err
	}
	return k, nil
}

func aeadOf(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func sealKeyfile(pt []byte) ([]byte, error) {
	key, err := loadKey()
	if err != nil {
		return nil, err
	}
	aead, err := aeadOf(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, pt, nil), nil
}

func openKeyfile(full []byte) ([]byte, error) {
	key, err := loadKey()
	if err != nil {
		return nil, err
	}
	aead, err := aeadOf(key)
	if err != nil {
		return nil, err
	}
	if len(full) < aead.NonceSize() {
		return nil, errors.New("secrets: blob demasiado corto")
	}
	nonce, ct := full[:aead.NonceSize()], full[aead.NonceSize():]
	return aead.Open(nil, nonce, ct, nil)
}
