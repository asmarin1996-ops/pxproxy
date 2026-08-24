package auth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"proxy/internal/config"
)

func LDAPLogin(cfg config.LDAPConfig, username, password string) (*UserClaims, error) {
	if username == "" || password == "" {
		return nil, errors.New("usuario y contraseña requeridos")
	}
	conn, err := ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: cfg.InsecureTLS, MinVersion: tls.VersionTLS12}))
	if err != nil {
		return nil, fmt.Errorf("conexión al servidor LDAP: %w", err)
	}
	defer conn.Close()

	upn := strings.TrimSpace(username)
	if cfg.BindUPNSuffix != "" && !strings.Contains(upn, "@") {
		upn = upn + "@" + cfg.BindUPNSuffix
	}
	if err := conn.Bind(upn, password); err != nil {
		return nil, errors.New("credenciales inválidas")
	}

	name, email := upn, upn
	var groups []string
	if cfg.BaseDN != "" {
		filter := "(sAMAccountName=%s)"
		if cfg.UserFilter != "" {
			filter = cfg.UserFilter
		}
		filter = strings.ReplaceAll(filter, "%s", ldap.EscapeFilter(strings.SplitN(username, "@", 2)[0]))
		req := ldap.NewSearchRequest(
			cfg.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			1,
			15,
			false,
			filter,
			[]string{"displayName", "mail", "memberOf"},
			nil,
		)
		if sr, serr := conn.Search(req); serr == nil && len(sr.Entries) > 0 {
			e := sr.Entries[0]
			if dn := e.GetAttributeValue("displayName"); dn != "" {
				name = dn
			}
			if m := e.GetAttributeValue("mail"); m != "" {
				email = m
			}
			groups = e.GetAttributeValues("memberOf")
		}
	}

	u := &UserClaims{Sub: "ldap|" + upn, Email: email, Name: name, Groups: groups}
	if !userAllowed(u, cfg.AllowedEmails, cfg.AllowedGroups) {
		return nil, errors.New("usuario no autorizado para este proxy")
	}
	return u, nil
}
