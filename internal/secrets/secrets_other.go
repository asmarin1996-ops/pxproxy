//go:build !windows

package secrets

import "errors"

const supported = false

var errNoDPAPI = errors.New("secrets: DPAPI no disponible en esta plataforma")

func dpapiSeal([]byte) ([]byte, error) { return nil, errNoDPAPI }

func dpapiOpen([]byte) ([]byte, error) { return nil, errNoDPAPI }
