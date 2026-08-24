# PxProxy — Documento Técnico

**Proxy inverso corporativo con autenticación Microsoft (Entra ID / Active Directory), 2FA opcional por usuario, gestión de certificados SSL y endurecimiento de seguridad perimetral.**

Versión del documento: 1.3 — Agosto 2026 (cluster multi-nodo PostgreSQL: recarga caliente, bloqueos compartidos, auditoría replicada, degradación elegante; incluye despliegue Ubuntu y endurecimiento v2)
Estado del proyecto: funcional y certificado mediante auditoría QA interna (ver sección 13).

---

## 1. Resumen ejecutivo

PxProxy es un proxy inverso escrito en Go (sin framework web externo) inspirado en Zoraxy. Expone sitios internos hacia internet enrutando por nombre de host (incluidos comodines `*.dominio`), exigiendo autenticación corporativa cuando la regla lo requiere, con soporte de:

- **Tres proveedores de identidad**: Microsoft Entra ID (OIDC/OAuth2), Active Directory on-premise (LDAP/LDAPS) y cuenta administradora local.
- **Verificación en dos pasos TOTP activable exclusivamente sobre los usuarios que el administrador decida** (sin obligatoriedad global).
- **Gestión completa de certificados SSL**: emisión y renovación automática vía Let's Encrypt (ACME) para los dominios expuestos, o carga de certificados propios por dominio, con panel de estado y renovación forzada.
- **Habilitar/deshabilitar dominios** desde el panel; los deshabilitados sirven una página estática endurecida (503) que informa que el servidor opera correctamente pero el dominio no está accesible.
- **Endurecimiento perimetral**: limitación de tasa, bloqueo por fuerza bruta, cabeceras de seguridad, verificación de origen anti-CSRF, límite de cuerpo, allowlist CIDR para el panel y registro de auditoría inmutable.

Todo se administra desde un panel web embebido en el binario (recursos `web/` incrustados con `go:embed`).

---

## 2. Arquitectura general

```
                        Internet
                           │
        ┌──────────────────┼───────────────────┐
        │ :80 proxy-http   │ :443 proxy-https  │  (puertos configurables;
        │  challenge ACME, │  TLS vía gestor    │   este equipo usa 8080/8443)
        │  redirect selectivo                 │
        └──────────────────┴───────────────────┘
                           │
              ┌────────────▼─────────────┐
              │  security.Chain(proxy)   │  Recover + SecureHeaders(false)
              └────────────┬─────────────┘
        ┌──────────────────┼──────────────────────┐
        │ GET /auth/login  │ GET /auth/attach     │  / → rules.Engine
        │  (→ panel)       │  (ticket SSO 60 s)   │     Handler(authCheck,
        └──────────────────┴──────────────────────┘     unauthorized)
                           │
                 lookup por Host (+wildcard)
             ┌───────────────┼────────────────┐
       regla deshabilitada  require_auth   proxy normal
       página endurecida    redirect a     httputil.ReverseProxy
       (503, CSP estricta)  login/401      X-Forwarded-* preservados

  Panel de administración: :8000 (admin_port)
    security.Chain(Recover, SecureHeaders(true), BodyLimit 1 MiB,
                   CheckOrigin, allowlist CIDR dinámica)
    Login (AD/LDAP/local) → [2FA si el usuario está en la lista] → sesión
    API REST /api/* + recursos web embebidos
```

Componentes internos (paquetes `internal/`):

| Paquete | Responsabilidad |
|---|---|
| `config` | Almacén JSON thread-safe (`Store.Get/Update/Save`), valores por defecto, regeneración de credenciales locales, tolerancia a BOM |
| `auth` | OIDC Entra ID, LDAP bind, login local, sesiones HMAC-SHA256 con época, tickets SSO, TOTP RFC 6238, flujo de segundo factor (`pending cookie` → desafío/inscripción) |
| `rules` | Motor de rutas por host con comodines, ReverseProxy por regla, página endurecida para dominios deshabilitados |
| `certs` | Gestor de certificados propios (disco `certs/<host>/`), sonda TLS en vivo, invalidación de caché ACME |
| `security` | Middleware reutilizables: Recover, SecureHeaders, BodyLimit, CheckOrigin, Limiter, AuditLog, utilidades CIDR/IP |
| `server` | Panel: páginas de login/2FA, API REST, plantillas embebidas, orquestación |

---

## 3. Estructura del proyecto

```
C:\Proxy\
├─ main.go                    Listeners (panel/proxy-http/proxy-tls), ACME, cableado
├─ go.mod / go.sum            Módulo "proxy"; deps: go-oidc/v3, oauth2, go-ldap/v3,
│                             x/crypto (bcrypt, autocert), skip2/go-qrcode
├─ pxproxy.exe                Binario compilado (Go 1.26.x)
├─ config.json                Estado persistente (creado al primer arranque)
├─ audit.log                  Auditoría JSONL (append-only)
├─ certs\<host>\fullchain.pem + privkey.pem   Certificados propios subidos
├─ acme-cache\                Caché DirCache de autocert (Let's Encrypt)
└─ internal\…
   ├─ config\config.go        Store + structs (Rule, TOTPConfig, ACMEConfig…)
   ├─ auth\auth.go            OIDC + sesiones + tickets SSO
   ├─ auth\ldap.go            Autenticación LDAP (bind como usuario)
   ├─ auth\local.go           Cuenta local (bcrypt)
   ├─ auth\totp.go            Núcleo TOTP RFC 6238 + ProvisionURI
   ├─ auth\login_flow.go      Cookie pendiente px_pending, NeedsSecondFactor,
   │                          CompleteLogin, inscripción/confirmación
   ├─ rules\engine.go         Motor de rutas + writeBlockedPage
   ├─ certs\certs.go          Manager de certificados + Probe + Renew
   ├─ security\security.go   Middlewares y utilidades de endurecimiento
   └─ server\admin.go         Panel completo (~1100 líneas): rutas, handlers,
                              plantillas login/2FA, política de contraseñas
```

---

## 4. Compilación y ejecución

Requisitos: Go ≥ 1.26 (PATH o anteponer `C:\Program Files\Go\bin`).

```powershell
cd C:\Proxy
go build -o pxproxy.exe .
go vet ./...
gofmt -w .
```

Ejecución como servicio oculto:

```powershell
Start-Process C:\Proxy\pxproxy.exe -WorkingDirectory C:\Proxy `
  -RedirectStandardOutput pxproxy.log -RedirectStandardError pxproxy.err `
  -WindowStyle Hidden
```

Puertos por defecto (editables en `config.json`; los cambios de puertos/listeners requieren reinicio):

| Puerto | Uso |
|---|---|
| 8000 | Panel de administración y autenticación |
| 80 | Proxy HTTP (desafío ACME + redirección selectiva) |
| 443 | Proxy HTTPS (gestor de certificados o par fijo `tls_cert_file/tls_key_file`) |

> Nota operativa: en equipos Windows donde HTTP.sys reserva 80/443, el arranque falla de forma **intencionalmente fatal** con mensaje claro; usar puertos altos (p. ej. 8080/8443, configuración actual de este despliegue).

Apagado ordenado: `Ctrl+C` (SIGINT) → `Shutdown` con drenaje de 5 s.

### 4.1 Despliegue en Ubuntu Server (objetivo principal)

Compilación cruzada desde cualquier plataforma:

```bash
make linux          # dist/pxproxy-linux-amd64 + dist/pxproxy-linux-arm64
./verify.sh         # gofmt + vet + test -race + build linux
```

Instalación en el servidor (como root):

```bash
sudo ./deploy/install.sh dist/pxproxy-linux-amd64
```

El instalador crea:

| Ruta | Contenido |
|---|---|
| `/usr/local/bin/pxproxy` | Binario |
| `/etc/pxproxy/config.json` | Configuración (+ `secrets.key`) — credenciales de fábrica `admin/Admin123!` |
| `/var/lib/pxproxy/` | Directorio de trabajo: `certs/`, `backups/`, `acme-cache/`, `audit.log` |
| `/etc/systemd/system/pxproxy.service` | Unidad systemd |

Características del servicio (`deploy/pxproxy.service`):

- Corre como usuario dedicado `pxproxy` (sin home, nologin) con **`CAP_NET_BIND_SERVICE`** → puede escuchar 80/443 sin ser root.
- `Restart=always` + `RestartSec=3`: auto-recuperación ante caídas.
- Hardening systemd: `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `NoNewPrivileges`, `LockPersonality`.
- Logs a journald: `journalctl -u pxproxy -f`. Auditoría JSONL sigue en `/var/lib/pxproxy/audit.log` (con su rotación propia).
- Firewall: el instalador abre 80/443/8000 en UFW si existe.

Actualización de versión:

```bash
sudo systemctl stop pxproxy
sudo install -m755 dist/pxproxy-linux-amd64 /usr/local/bin/pxproxy
sudo systemctl start pxproxy
```

### 4.2 Despliegue real verificado (Ubuntu 24.04.4 LTS)

Ejecutado y certificado el 24/08/2026 sobre `<IP-DEL-SERVIDOR>` (Ubuntu Server 24.04.4, systemd 255):

| Verificación | Resultado |
|---|---|
| Instalación (`install.sh`) | Usuario `pxproxy`, `/etc/pxproxy`, `/var/lib/pxproxy`, binario y unidad creados |
| Servicio systemd | `active` + `enabled` (arranque con el sistema), logs en journald |
| Puerto 80 como no-root | OK vía `CAP_NET_BIND_SERVICE` (`AmbientCapabilities`) |
| Cifrado Linux | `secrets.key` auto-creada (32 bytes, 0600) + secretos `enc1:` (AES-256-GCM) |
| Login local | `admin/Admin123!` → cookie de sesión, `is_admin:true`, aviso de contraseña por defecto |
| Proxy E2E | Regla `app.local → :3000`; `curl -H "Host: app.local" http://<ip>/` devolvió contenido del upstream por el puerto 80 |
| Dominio deshabilitado | HTTP 503 con página endurecida "Dominio no accesible"; reactivación instantánea |
| Persistencia | `systemctl restart pxproxy`: sesión previa sigue válida (descifrado AES-GCM en caliente); reglas intactas |
| Auditoría/limpieza | Regla de prueba eliminada, upstream temporal retirado, servidor quedó con servicio activo y sin reglas |

Notas operativas:

- La primera configuración (`POST /api/setup`) solo se acepta desde loopback sin proveedores configurados; el resto del ciclo de vida se gestiona ya autenticado desde el panel.
- El binario acepta flags de arranque que sobrescriben puertos **sin persistirlos**: `-admin-port`, `-proxy-http-port`, `-proxy-https-port` (imprescindibles para multi-nodo, ver 4.3).

### 4.3 Cluster multi-nodo con PostgreSQL (v2.0)

PxProxy admite **N instancias idénticas compartiendo estado** en PostgreSQL. El plano de datos (tráfico proxy) nunca depende de la BD: se sirve desde memoria con la última configuración buena.

**Arquitectura**

| Componente | Implementación |
|---|---|
| Paquete | `internal/store`: interfaz `ConfigBackend`/`LockBackend`/`AuditBackend` con `FileBackend` (por defecto) y `PgBackend` (`pgx/v5`) |
| Esquema (auto-migrado) | `pxproxy_config` (config JSONB, fila única), `pxproxy_locks` (bloqueos por limitador), `pxproxy_audit` (eventos append-only indexados por ts/evento) |
| Escritor único | `pg_advisory_xact_lock` en cada escritura → sin conflictos entre nodos |
| Recarga en caliente | `LISTEN pxproxy_changes` + fallback de sondeo cada 30 s comparando versión; al cambiar: refresco de reglas y proveedores sin reinicio |
| Bloqueos compartidos | Guardado cada 30 s con **merge** (prevalece el `locked_until` más nuevo); carga y restauración cada 30 s → convergencia ≤60 s en ambos sentidos |
| Auditoría dual | Siempre escribe JSONL local rotado + réplica asíncrona a `pxproxy_audit` |
| Secretos | DSN y demás secretos cifrados en la propia BD (`enc1:`); **todos los nodos del cluster deben compartir la misma `secrets.key`** (si no, el nodo rechaza la config remota con error explícito en vez de arrancar corrupto) |

**Activación** (en `config.json`, el DSN se sella solo en el siguiente guardado):

```json
"storage": { "backend": "postgres", "dsn": "postgres://pxproxy:CLAVE@127.0.0.1:5432/pxproxy?sslmode=disable" }
```

Segundo nodo en el mismo host: copiar `/etc/pxproxy/{config.json,secrets.key}` a su directorio de trabajo y arrancar con `-admin-port 8001 -proxy-http-port 8081 -proxy-https-port 8444`.

**Comportamiento ante caída de la BD (verificado)**

1. Tráfico proxy: **sigue sirviendo** sin interrupción.
2. Panel/API: login y consultas funcionan (estado en memoria).
3. Cambios de config: se guardan solo localmente; si la BD muere *después* de un arranque correcto la API devuelve error explícito; si el nodo *arrancó* degradado guarda en silencio en modo fichero. En ambos casos `GET /api/health` refleja `"storage":{"ok":false}`.
4. Recuperación: al volver la BD, el sondeo detecta la versión, reconecta LISTEN/NOTIFY y reactiva las réplicas automáticamente. Los cambios hechos en degradado **no se replican** (semántica last-known-good; el cluster manda).

**Certificación E2E (24/08/2026, PostgreSQL 16.15 en `<IP-DEL-SERVIDOR>`)**

| Prueba | Resultado |
|---|---|
| Dos nodos (8000/80 + 8001/8081) sobre la misma BD | Ambos `health: storage.ok=true` con misma versión |
| Regla creada vía nodo A servida por nodo B sin reinicio | OK (≤3 s vía NOTIFY) |
| Lockout por IP creado contra nodo B bloquea login correcto en nodo A | OK (`error=Demasiados intentos fallidos`) |
| Auditoría replicada | 10 eventos (`login_failed/blocked/success`) visibles por SQL |
| DSN sellado en BD | `enc1:` confirmado en `pxproxy_config.data->storage->dsn` |
| PG caído: tráfico, health degradada, recuperación automática | OK (cambio no replicado descartado correctamente) |

Bug corregido durante la certificación: deadlock en `SetBackend` (reentrancia de `saveMu` vía `persistLocal`) que solo se manifestaba adjuntando backend — añadida ruta `persistLocalLocked`.

---

## 5. Referencia de `config.json`

| Clave | Tipo | Descripción |
|---|---|---|
| `admin_port` | int | Puerto del panel (8000) |
| `proxy_http_port` / `proxy_https_port` | int | Puertos del plano proxy (80/443 por defecto; 8080/8443 aquí) |
| `tls_cert_file` / `tls_key_file` | string | Par PEM fijo global (alternativa sin ACME ni certs propios) |
| `panel_tls_cert_file` / `panel_tls_key_file` | string | Par PEM para servir el **panel por HTTPS** (opcional; requiere reinicio) |
| `session_hours` | int | Vida de la cookie de sesión |
| `session_secret` | hex | Secreto HMAC generado aleatoriamente; rota al revocar sesiones; **cifrado en reposo con DPAPI** (`dpapi1:`) |
| `session_epoch` | int | Época de sesión; las cookies con época distinta son inválidas |
| `secure_cookies` | bool | Fuerza atributo `Secure` (obligatorio si el panel sirve por HTTPS) |
| `insecure_upstream` | bool | Tolera TLS autofirmado del upstream |
| `admin_allowed_cidrs` | []string | Allowlist CIDR del panel (vacío = sin restricción) |
| `panel_admins` | []string | Identidades con rol de administración del panel (**vacío = cualquier autenticado administra**, comportamiento compatible); si se llena, el resto ve 403 en páginas y API |
| `login_max_fails` / `lockout_minutes` | int | Umbrales del bloqueo por fuerza bruta (5 / 15) |
| `acme` | objeto | `{enabled, domains[], redirect_http, cache_dir}` — Let's Encrypt |
| `azure` | objeto | Entra ID: client_id/secret/tenant, redirect_url, allowed_emails/groups |
| `ldap` | objeto | url(ldaps), base_dn, bind_upn_suffix, user_filter, insecure_tls, enabled |
| `local_admin` | objeto | `{enabled, username, password_hash(bcrypt)}` — hash vacío regenera `admin/Admin123!` |
| `totp` | objeto | `{enabled, require_for[], secrets{identidad:{secret,confirmed}}}` |
| `rules` | array | `{host, target, require_auth, enabled}` |

Los secretos sensibles (`session_secret`, `azure.client_secret`, `totp.secrets.*.secret`) se cifran **en reposo**: en Windows con DPAPI (`dpapi1:`, ámbito CurrentUser) y en Linux con **AES-256-GCM usando la clave hermana `secrets.key`** (32 bytes aleatorios, creada con permisos 0600 junto a `config.json`; prefijo `enc1:`). `Open` entiende ambos formatos, lo que permite migrar un `config.json` entre plataformas regenerando solo los valores indescifrables. En memoria y en la API siempre viajan en claro/enmascarados. El archivo vive con permisos 0600.

Cada guardado genera antes una copia del estado previo en `backups/config-<timestamp>.json` (se conservan las 10 más recientes). **Válvula de escape anti-bloqueo**: si `panel_admins` deja fuera a todos los administradores reales, editar ese array a `[]` en `config.json` (con el servicio detenido) y reiniciar restaura el acceso; lo mismo permite inspeccionar cualquier `backups/`.

| `acme` | objeto | `{enabled, domains[], redirect_http, cache_dir}` — Let's Encrypt |

---

## 6. Autenticación e identidad

### 6.1 Microsoft Entra ID (OIDC)
- Flujo Authorization Code **con PKCE (S256)**: `code_verifier` aleatorio de 64 caracteres guardado en la cookie `px_state` junto a nonce y URL de retorno; el callback envía `oauth2.VerifierOption` en el intercambio. Mitiga robo de código de autorización.
- Flujo Authorization Code con `state` firmado (cookie `px_state`, sufijo `.state`).
- Callback valida estado, intercambia código, mapea claims (`sub`, `email`/`preferred_username`, grupos).
- Listas blancas opcionales por correo exacto o dominio (`@empresa.com`) y por grupos.
- Configuración asistida por pantalla inicial de setup cuando no existe ningún método activo.

### 6.2 Active Directory on-premise (LDAP/LDAPS)
- Bind directo con las credenciales del usuario (UPN construido con `bind_upn_suffix`, filtro configurable, por defecto `(sAMAccountName=%s)`).
- Grupos recuperados para autorización; advertencia en log si `insecure_tls=true`.

### 6.3 Cuenta local
- bcrypt; credenciales de fábrica `admin` / `Admin123!` (regeneradas si `password_hash` queda vacío), con aviso persistente en log y panel mientras no se cambie.
- Cambio protegido por contraseña actual + política de fortaleza (sección 10.5).

### 6.4 Sesiones
- Cookie `px_session`: payload Base64URL `{sub,email,name,groups,epoch,exp}` + HMAC-SHA256. HttpOnly, SameSite=Lax, Secure opcional.
- **Revocación global** (`POST /api/sessions/revoke`): rota secreto e incrementa época → toda cookie previa muere instantáneamente (verificado: epoch 0→1, acceso posterior 401).

### 6.5 SSO para sitios proxeados
Al acceder a una regla con `require_auth` sin sesión, el proxy redirige al panel; tras autenticarse, el panel emite un **ticket firmado de 60 s** con audiencia = hostname solicitado (`GET /auth/attach?t=…&rd=…`), canjeable una sola vez en el origen del proxy para establecer la sesión allí. Evita re-login por sitio.

---

## 7. Verificación en dos pasos (TOTP) — activación por usuario

**Filosofía: nadie tiene 2FA obligatorio por defecto; solo los usuarios incluidos explícitamente en `totp.require_for` lo atraviesan.**

Identidades admitidas en la lista: correo de Entra ID, UPN/sAMAccountName LDAP, nombre del usuario local, o dominio completo `@empresa.com`. El emparejamiento evalúa múltiples candidatos de identidad (correo, parte local del correo, usuario tras `|` del `sub`), lo que permite escribir simplemente `admin` para el administrador local.

Flujo (100 % verificado en QA con códigos RFC reales):

1. Usuario en lista inicia sesión → no recibe sesión aún; recibe cookie firmada **`px_pending`** (5 min) y redirección:
   - sin dispositivo inscrito → `/auth/2fa/enroll`
   - ya inscrito → `/auth/2fa` (desafío)
2. **Inscripción**: QR (`otpauth://totp/PxProxy:…`, SHA1, 6 dígitos, periodo 30 s) generado en memoria con `skip2/go-qrcode` + clave manual espaciada. La confirmación exige un código vigente (±1 ventana); al validarla se marca `confirmed` y se emite sesión.
3. **Desafío** siguiente accesos: formulario de 6 dígitos; errores y abusos limitados (`limTOTP`, 6 fallos/10 min).
4. **Reset por identidad** (`POST /api/totp/reset`) → próxima sesión vuelve a inscribirse (útil para pérdida de teléfono).
5. Quitar al usuario de la lista restaura su acceso directo sin segundo paso (y su inscripción queda latente).

Detalles técnicos: HMAC-SHA1 sobre contador `floor(Unix/30)`, truncamiento estándar RFC 4226, comparación en tiempo constante, ventana ±1. Los secretos viven en `config.json` bajo `totp.secrets` y se enmascaran en la API de configuración.

---

## 8. Proxy inverso: reglas de dominio

- Enrutado por `Host` normalizado (minúsculas, sin puerto), con **comodines** `*.dominio` y precedencia por coincidencia más larga; exacto gana sobre comodín.
- `ReverseProxy` con `Rewrite`: conserva Host original y añade `X-Forwarded-For/Proto/Host` (verificado en QA con eco del upstream).
- `require_auth=true` protege el sitio: navegadores → redirección al login con retorno; clientes API → `401 {"error":"autenticacion requerida"}`.
- Hot-reload: cada cambio de reglas reconstruye el mapa atómicamente (`Rebuild`), sin reinicio.
- Validaciones de entrada: `host` contra expresión regular estricta (opcional `*.`), `target` solo http/https con host válido → 400 en caso contrario.

### 8.1 Habilitar / deshabilitar dominios
Cada regla posee interruptor `enabled` (toggle por fila en el panel). Un dominio **deshabilitado no desaparece**: responde siempre

- **HTTP 503** con página estática 100 % embebida (cero JavaScript, cero recursos externos, cero reflexión de entrada) que indica: *«El servidor funciona correctamente. Este dominio no está accesible en este momento.»*
- Cabeceras endurecidas propias: CSP `default-src 'none'; script-src 'none'; … frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Robots-Tag`.
- La comprobación de deshabilitado precede a `require_auth`, así que ni siquiera filtra que el sitio existe para anónimos (mismo 503 para todos).

---

## 9. Gestión de certificados SSL/TLS

Objetivo: gestionar, generar y renovar certificados de todo lo expuesto, con dos orígenes combinables.

### 9.1 Let's Encrypt (ACME automático)
- Interruptor `acme.enabled` + dominios adicionales opcionales; **todo host de las reglas queda automáticamente autorizado** para emisión (HostPolicy dinámica evaluada en caliente contra la configuración vigente).
- Desafío HTTP-01 servido siempre en el listener :80 (`/.well-known/acme-challenge/*` nunca se redirige ni intercepta).
- Caché `autocert.DirCache` (`acme-cache/`); renovación automática estándar de autocert dentro de su ventana de 30 días.
- **Renovación forzada** (`POST /api/certs/renew`): invalida la entrada de caché del dominio (tolerante al formato interno de claves) → próximo acceso/sonda re-emite. Registrado en log y auditoría.
- **Redirección HTTP→HTTPS optativa y quirúrgica**: solo se redirigen hosts que tendrán certificado (propios o ACME-autorizados); el resto sigue respondiendo por HTTP sin romperse.

### 9.2 Certificados propios por dominio
- Subida por panel/API de fullchain + clave PEM; validación estricta (`tls.X509KeyPair`, parseo de leaf para subject/issuer/not_after); rechazo claro ante par mismatched o PEM vacío.
- Persistencia en `certs/<host>/` con escritura atómica (tmp+rename) y permisos 0600/0700; recargados al arranque.
- Precedencia en handshake: propio → ACME → error limpio. TLS mínimo 1.2.

### 9.3 Observabilidad
- `GET /api/certs`: inventario (reglas ∪ dominios ACME ∪ propios) con origen, subject, issuer y vigencia de los propios.
- `GET /api/certs/status`: **sonda TLS real** (handshake local contra el listener HTTPS con SNI por dominio) que devuelve emisor y `not_after` efectivos, o el error exacto.

---

## 10. Endurecimiento de seguridad

| Mecanismo | Detalle |
|---|---|
| Cabeceras | Panel: CSP restrictiva, nosniff, frame-deny, opener-policy. Página bloqueo: CSP `none` total |
| Anti-CSRF | `CheckOrigin`: POST con Origin externo → 403 |
| Límite de cuerpo | 1 MiB en panel → 413 correcto (`MaxBytesError` mapeada) |
| Fuerza bruta | Limitadores por IP y por usuario (5 fallos/15 min → lockout configurable) con mensaje explícito; limitador dedicado para códigos 2FA. **Estado persistido** en `limiters.json` (snapshot cada 30 s y al apagar; se restaura al arrancar y se borra solo cuando queda vacío) → los bloqueos sobreviven reinicios |
| Rol administrador | `panel_admins`: gate en `requireAPI`/`requirePage`; sin rol → API 403 JSON y páginas 403 HTML. `/api/session` expone `is_admin` para la UI |
| Panel TLS | Opción `panel_tls_cert_file/key_file` para servir el panel por HTTPS propio (aviso si `secure_cookies=false`) |
| Secretos en reposo | DPAPI (`dpapi1:`) sobre session_secret, client_secret y secretos TOTP |
| Backups config | `backups/config-*.json`, 10 más recientes, creados antes de cada escritura |
| Auditoría | `audit.log` JSONL append-only con **rotación por tamaño (10 MiB)** a `audit-<timestamp>.log` conservando las 5 más recientes: eventos `login_success/login_failed/login_blocked/password_changed/setup_completed/rule_upsert/rule_delete/config_update/totp_*/cert_*/sessions_revoked` con IP y detalle |
| Allowlist panel | CIDRs opcionales (`admin_allowed_cidrs`) evaluadas dinámicamente |
| Contraseñas | ≥12 chars + mayús/minús/dígito/símbolo + denegación de patrones comunes con **normalización leetspeak** (Adm1n→admin) |
| Auditoría | `audit.log` JSONL append-only: `login_success/login_failed/login_blocked/password_changed/setup_completed/rule_upsert/rule_delete/config_update/totp_*/cert_*/sessions_revoked` con IP y detalle |
| Sesiones | Firma HMAC + época revocable + expiración; cookies HttpOnly/SameSite |
| Errores | `Recover` en ambos planos; fallos de arranque de listener son fatales y visibles (sin zombies silenciosos) |
| Dependencias | `govulncheck` ejecutado: **0 vulnerabilidades** alcanzables (x/crypto actualizado a v0.55.0) |

---

## 11. Referencia API (panel :8000)

Autenticación: cookie de sesión salvo `*` marcado. Escrituras validan origen.

| Método Ruta | Propósito |
|---|---|
| GET `/api/session`* | Estado: autenticado, setup_required, métodos activos, default_password, **is_admin** |
| GET `/api/health`* | Sonda de salud del panel (`{"ok":true,"uptime_seconds":N}`) |
| GET/POST `/api/rules` · POST `/api/rules/delete` | CRUD de reglas (upsert por host) |
| GET/POST `/api/config` | Lectura enmascarada / actualización parcial de ajustes |
| POST `/api/setup` | Asistente inicial (LDAP u operación mínima) |
| POST `/api/ldap-test` | Prueba de conexión/bind LDAP |
| POST `/api/local-password` | Cambio de contraseña local (política aplicada) |
| POST `/api/sessions/revoke` | Revoca TODAS las sesiones (rotación secreto + época) |
| GET `/api/security` | Resumen de endurecimiento activo |
| GET `/api/totp` | Estado 2FA: lista de usuarios e inscripciones |
| POST `/api/totp/settings` | Define `require_for[]` (única vía de activación por usuario) |
| POST `/api/totp/reset` | Borra inscripción de una identidad |
| GET `/api/certs` | Inventario de certificados y ajustes ACME |
| GET `/api/certs/status` | Sonda TLS en vivo por dominio |
| POST `/api/certs/acme` | enabled/domains/redirect_http |
| POST `/api/certs/custom` · `/custom/delete` | Alta/baja de certificado propio |
| POST `/api/certs/renew` | Forzar reemisión ACME |
| GET `/auth/login` · POST `/auth/login/ldap` · `/auth/login/local` | Accesos |
| GET `/auth/callback` | OAuth2 callback Entra ID |
| GET `/auth/logout` | Limpieza de cookie |
| GET `/auth/2fa` · POST `/auth/2fa/verify` | Desafío TOTP |
| GET `/auth/2fa/enroll` · POST `/auth/2fa/enroll/confirm` | Inscripción QR |

Plano proxy (:80/:443): `GET /healthz` (`{"ok":true}` sin auth), `GET /auth/login` (puente al panel), `GET /auth/attach` (canje ticket SSO), `/*` motor de reglas.

---

## 12. Panel web

SPA ligera sin frameworks (`web/index.html + app.js + style.css + favicon.svg`, embebidos).

**Identidad visual**: escudo propio de PxProxy (silueta facetada con ruta escalonada de tráfico y dos nodos, gradiente azul→cian) presente como logo en la barra lateral, como marca de las páginas de login y como favicon (`/favicon.svg`, SVG vectorial servido con MIME `image/svg+xml`).

**Navegación por secciones**: barra lateral fija (colapsa a barra superior horizontal en pantallas <900px) con acceso directo a Estado, Reglas de proxy, Ajustes, Identidad (Entra/LDAP/local + test LDAP + cambio de clave), Seguridad (CIDR, administradores, lockout, cookies seguras, revocación global), 2FA/TOTP (lista de usuarios y dispositivos inscritos/reset) y Certificados SSL (ACME, subida PEM, tabla con verificación en vivo, renovar, borrar). El sistema de vistas (`data-view-name` + hash `#seccion`) mantiene la sección activa al recargar; la cabecera de Estado muestra píldora de salud en vivo (`/api/health`).

Página de login glassmorphism con escudo, pestañas según métodos activos, mostrar/ocultar contraseña y mensajes inline. Página 403 para usuarios sin rol de administración.

---

## 13. Auditoría QA (certificación interna)

Metodología: caja negra E2E contra binario real + análisis de causa raíz; arnés PowerShell + upstream eco + generador TOTP independiente conforme a RFC.

### 13.1 Defectos encontrados y corregidos

| # | Severidad | Defecto | Corrección |
|---|---|---|---|
| 1 | CRÍTICO | TOTP dividía segundos Unix entre `time.Duration` en nanosegundos → contador constante 0, códigos estáticos inutilizables con apps reales | Divisor corregido en `TOTPCode`/`VerifyTOTPCode`; rotación verificada cada 30 s |
| 2 | CRÍTICO | Recursión infinita en `writeDecodeErr` → stack overflow tumbaba el proceso ante cualquier JSON inválido | Llamada restablecida; regresión 400 limpia sin caída |
| 3 | ALTO | Fallo de bind dejaba proceso zombie sin proxy ni aviso | Arranque de listener ahora fatal con diagnóstico |
| 4 | MEDIO | Límite de cuerpo devolvía 400 genérico | `MaxBytesError` → 413 específico |
| 5 | MEDIO | Política de contraseñas evadible con leetspeak | Normalización antes de patrones |
| 6 | BAJO | BOM UTF-8 en config.json impedía arrancar | TrimPrefix en carga |

### 13.2 Matriz resumen de pruebas ejecutadas (todas PASS tras correcciones)

- Sesión/panel: login ok/fallo, flags de cookie, logout, revocación global invalidante, semántica `/api/session`.
- Reglas: alta, proxy positivo + cabacas X-Forwarded, wildcard, 404 propio, inválidos 400, borrado, require_auth ×3 modos.
- Dominios on/off: conmutación proxy↔página endurecida 503 (cabeceras, sin reflexión, mensaje), también sobre HTTPS.
- Endurecimiento: cabeceras, 413, cross-origin 403, lockout con mensaje y eventos de auditoría.
- Contraseñas: 6 débiles fuera (post-leet incluido), fuerte aceptada, antigua inválida, evento `password_changed`.
- 2FA: activación SOLO por lista; enrolamiento QR (secreto mostrado == almacenado), confirmación con código válido → sesión; reingreso → desafío; falso rechazado; verdadero entra; reset; lista vacía → acceso directo.
- Certificados: subida válida, mismatch rechazado, inventario con vigencia, listener TLS automático, sonda viva, handshake real `curl -k --resolve`, renovación custom bien orientada, borrado, roundtrip ACME, renovación forzada con invalidación de caché registrada, redirect selectivo, desafío ACME intacto.
- Humo final: restauración prístina (`Admin123!` + aviso), proxy operativo, auditoría activa.

Falsos positivos del arnés descartados (no defectos): Host header incorrecto contra :80 inicial (respondía HTTP.sys del sistema), regex de mensaje, Location URL-encoded, expectativa 200 en `/api/session`, extractor de secreto capturando base64 del QR, serialización PS5.1 de PEM como objeto (el servidor rechazó correctamente), PATH de Go entre shells.

### 13.3 Residuales aceptados
- Logout es client-side (sesiones stateless); revocación fuerte vía endpoint dedicado.
- Emisión LE real requiere dominio público alcanzable; generación/renovación/invalidez quedan certificadas funcionalmente.
- Cambios de puertos/listeners TLS (incluido el del panel) requieren reinicio (indicado en UI).
- Cerrados en la fase de endurecimiento v2 (sección 10): rol administrador, TLS del panel, secretos cifrados en reposo, PKCE, bloqueos persistentes, rotación de auditoría y backups de configuración.

---

## 14. Flujos clave (secuencia resumida)

**Login local con 2FA activado**
```
POST /auth/login/local → credenciales OK → ¿en require_for?
  sí → IssuePending(px_pending 5min) → 302 /auth/2fa[/enroll]
       verify|confirm(código ±1 ventana) → IssueSession → 302 destino
  no → IssueSession → 302 destino
```

**Solicitud a sitio protegido**
```
GET https://sitio.dominio/ → Engine.lookup(host) → require_auth & sin sesión
  → 302 panel:/auth/login?rd=URI → autenticación [+2FA]
  → RedirectAfterAuth → /auth/attach?t=TICKET&rd=https://sitio.../
  → canje (60s, audiencia=host) → cookie en plano proxy → contenido
```

**Certificado de dominio nuevo**
```
Regla creada → HostPolicy lo autoriza → primer handshake/sonda
  → ACME HTTP-01 (listener :80, desafío exento de redirect) → emisión
  → autocert renueva en ventana; /api/certs/renew fuerza reemisión
```

---

## 15. Pruebas automatizadas (`go test ./...`)

La matriz QA manual quedó congelada en suites Go ejecutables (7 paquetes, todos verdes):

| Suite | Cobertura |
|---|---|
| `auth/totp_test.go` | Vectores oficiales RFC 6238 SHA1, rotación cada 30 s dentro/fuera de ventana, rechazo de formatos inválidos y secretos cortos, URI de provisión |
| `auth/pkce_test.go` | Vector oficial RFC 7636 S256; `/auth/login` emite `code_challenge`+método y cookie de 3 partes cuyo verifier reproduce el challenge |
| `server/password_test.go` | Política: fuertes aceptadas, débiles y patrones comunes rechazadas, **evasión leetspeak bloqueada** |
| `rules/engine_test.go` | Normalización de host, precedencia exacta vs comodín, página endurecida 503 con CSP/cabeceras y sin reflexión de host, 404 sin regla |
| `config/config_test.go` | Tolerancia a BOM, regeneración de credenciales por defecto, **sellado DPAPI en disco con texto claro solo en memoria**, creación/poda de backups, round-trip de secretos entre recargas |
| `secrets/secrets_windows_test.go` | Round-trip DPAPI, idempotencia del sellado, paso a través de texto plano |
| `security/security_test.go` | Lockout/reset del limitador, **Snapshot→Restore preserva contadores**, rotación de auditoría con umbral pequeño y poda |

Hallazgos que estos tests destaparon durante su redacción (y quedaron corregidos): use-after-free al copiar el blob DPAPI antes de `LocalFree`; y tres aserciones mal planteadas del arnés inicial (vectores HOTP de 8 dígitos vs sufijo TOTP de 6, ventana no alineada a múltiplo de 30 s, URL de retorno relativa que la sanitización rechaza correctamente).

---

## 16. Créditos de dependencias

`github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2` (con PKCE), `github.com/go-ldap/ldap/v3`, `golang.org/x/crypto` v0.55.0 (bcrypt, acme/autocert), `golang.org/x/sys/windows` (DPAPI), `github.com/skip2/go-qrcode`. Resto: biblioteca estándar de Go.
