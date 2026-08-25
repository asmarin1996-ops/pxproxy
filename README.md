# PxProxy

![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/Licencia-MIT-green)
![Platform](https://img.shields.io/badge/Plataforma-Linux%20%7C%20Windows-blue)

Proxy inverso HTTP/HTTPS con autenticación corporativa (Entra ID / LDAP / admin local), panel de administración web, 2FA TOTP opcional por usuario, load balancing, health checks, dashboard en tiempo real, métricas Prometheus, gestión de certificados (ACME y propios) y **cluster multi-nodo con estado compartido en PostgreSQL**. Escrito en Go puro, sin dependencias de runtime.

## Características

- **Proxy por dominio virtual**: cada `host` enruta a su upstream con cabeceras X-Forwarded-*; dominio deshabilitado → página endurecida 503.
- **Load balancing**: round-robin, ponderado (weighted) y menos conexiones (least-connections) por dominio con múltiples backends.
- **Health checks de upstreams**: probing HTTP periódico con circuit breaker (N fallos → DOWN, 1 OK → UP), métricas por backend.
- **Dashboard en tiempo real**: gráficas de conexiones activas, RPS, latencia, memoria y estado de backends via Chart.js.
- **Métricas Prometheus**: endpoint `/metrics` con 10 métricas (requests, duration, active conns, storage ok, upstream health, uptime, memory, goroutines).
- **Logger estructurado JSON**: niveles debug/info/warn/error, componentes, request_id; compatible con `*log.Logger`.
- **Autenticación**: Entra ID (OAuth2 + PKCE S256), LDAP/AD o admin local bcrypt. Bloqueos por IP/usuario con ventana deslizante y persistencia.
- **2FA TOTP** obligatorio opcionalmente por identidad (`totp.require_for`).
- **Certificados**: ACME (Let's Encrypt) con redirect HTTP→HTTPS o PEM propio por SNI; TLS del panel opcional (HTTP por defecto).
- **Panel web** embebido: estado, dashboard, reglas, ajustes, identidad, seguridad, backups, 2FA, certificados. Rol `panel_admins` + escape hatch local.
- **Cluster multi-nodo** (v2.0): configuración, bloqueos y auditoría compartidos en PostgreSQL; recarga en caliente LISTEN/NOTIFY; escritor único vía advisory locks; degradación elegante si la BD cae (el tráfico nunca se detiene).
- **Backup/Restore BD**: snapshots JSON atómicos, auto-scheduler configurable, API + CLI + UI con crear/listar/restaurar/eliminar.
- **Secretos cifrados en reposo**: DPAPI (Windows) o AES-256-GCM con `secrets.key` (Linux); formatos interoperables.
- **Auditoría** JSONL rotada local + réplica a tabla SQL cuando hay cluster.
- **CI/CD**: GitHub Actions con build linux+windows, vet, test -race, upload artifacts.
- **Hardening**: CSP estricta, límites de cuerpo/cabeceras, verificación Origin, HSTS, backups previos a cada cambio con retención, systemd hardening completo.

## Inicio rápido (Ubuntu Server)

```bash
make linux                                  # dist/pxproxy-linux-amd64 (+arm64)
sudo ./deploy/install.sh dist/pxproxy-linux-amd64   # systemd + usuario dedicado + firewall
```

Panel: `http://<ip>:8000` — credenciales de fábrica `admin/Admin123!` (cámbialas al primer acceso).

Segundo nodo del cluster:

```bash
sudo mkdir -p /var/lib/pxproxy-node-b && sudo cp /etc/pxproxy/{config.json,secrets.key} /var/lib/pxproxy-node-b/
sudo chown -R pxproxy:pxproxy /var/lib/pxproxy-node-b
sudo -u pxproxy /usr/local/bin/pxproxy -config /var/lib/pxproxy-node-b/config.json \
    -admin-port 8001 -proxy-http-port 8081 -proxy-https-port 8444
```

Modo Windows: `go build -o pxproxy.exe . && ./pxproxy.exe -config config.json`.

### Cluster PostgreSQL

```json
"storage": { "backend": "postgres", "dsn": "postgres://pxproxy:CLAVE@127.0.0.1:5432/pxproxy?sslmode=disable" }
```

Esquema auto-migrado (`pxproxy_config`, `pxproxy_locks`, `pxproxy_audit`). Todos los nodos comparten la misma `secrets.key`.

## Desarrollo

```bash
./verify.sh        # gofmt + vet + test -race + builds linux
go test ./...      # suites unitarias
PXPX_TEST_PG_DSN='postgres://...' go test ./internal/store/   # integración PostgreSQL
```

Estructura: `internal/auth` (OIDC/LDAP/sesiones/TOTP) · `internal/server` (panel API+UI) · `internal/rules` (enrutado) · `internal/config` · `internal/store` (fichero/PostgreSQL) · `internal/security` (limiters/audit/middleware) · `internal/certs` (ACME/SNI) · `internal/secrets` (DPAPI/AES-GCM) · `web/` (UI embebida).

Documentación técnica completa: [`DOCUMENTO_TECNICO.md`](DOCUMENTO_TECNICO.md) — incluye referencia de configuración, API, hardening, despliegue Ubuntu y certificación E2E del cluster.

## Seguridad

Reporta vulnerabilidades por los canales privados acordados con el mantenedor; no abras issues públicas para ellas.

## Licencia

[MIT](LICENSE) — úsalo, modifícalo y distribúyelo libremente.

## Apoya el proyecto

Si PxProxy te resulta útil, considera apoyar su desarrollo:

- **GitHub Sponsors**: [github.com/sponsors/asmarin1996-ops](https://github.com/sponsors/asmarin1996-ops)
- **Ko-fi**: [ko-fi.com/asmarin1996](https://ko-fi.com/asmarin1996)

Las donaciones ayudan a mantener el proyecto: nuevas funciones, correcciones de seguridad y mejor documentación. Gracias por tu apoyo.
