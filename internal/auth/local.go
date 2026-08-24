package auth

import (
	"errors"
	"strings"

	"proxy/internal/config"
)

func LocalLogin(cfg config.LocalAdminConfig, username, password string) (*UserClaims, error) {
	if !cfg.Enabled {
		return nil, errors.New("la cuenta local esta deshabilitada")
	}
	if strings.TrimSpace(username) == "" || password == "" {
		return nil, errors.New("usuario y contrasena requeridos")
	}
	if !strings.EqualFold(strings.TrimSpace(username), cfg.Username) {
		return nil, errors.New("credenciales invalidas")
	}
	if err := config.CheckPassword(cfg.PasswordHash, password); err != nil {
		return nil, errors.New("credenciales invalidas")
	}
	return &UserClaims{
		Sub:   "local|" + strings.ToLower(cfg.Username),
		Email: cfg.Username + "@local",
		Name:  "Administrador local",
	}, nil
}
