# ACCESO AL REPOSITORIO — guía para continuar mañana

Objetivo: poder trabajar y acceder al código desde cualquier sitio usando GitHub.

## Estado actual (todo listo)

- ✅ Repositorio git inicializado en `C:\Proxy` (rama `main`) con **commit inicial hecho**
- ✅ `.gitignore` protege los secretos: `config.json`, `secrets.key`, `limiters.json`, `audit.log*`, `backups/`, `certs/`, logs y binarios **nunca se subirán**
- ✅ `config.example.json` incluido como plantilla pública de configuración
- ✅ `README.md` renovado + `DOCUMENTO_TECNICO.md` v1.3 (toda la evidencia del proyecto)
- ⏳ Único paso pendiente: que TÚ crees la cuenta y el repositorio remoto (ver abajo) — son ~5 minutos

> ⚠️ Por qué no hay credenciales escritas en este archivo: una contraseña dentro de un repo es el error nº1 de seguridad en GitHub (cualquier push accidental a público = fuga). Tus credenciales viven SOLO en tu gestor de contraseñas / GitHub.

## Paso 1 — Crear tu cuenta (2 min)

1. Entra en <https://github.com/signup> con tu email personal o corporativo.
2. Verifica el email, elige nombre de usuario (ej.: `tuusuario`).
3. Activa 2FA cuando te lo pida (app autenticadora; guarda los códigos de recuperación).

## Paso 2 — Crear el repositorio (1 min)

1. En <https://github.com/new> crea un repo llamado `pxproxy`.
2. **Elígelo PRIVADO** — importante: la documentación técnica incluye topología interna (IPs de laboratorio).
3. NO inicialices con README ni .gitignore (ya los tenemos).

## Paso 3 — Subir el código (elige UNA opción)

### Opción A — GitHub CLI (recomendada, también sirve desde cualquier sitio después)

```powershell
winget install --id GitHub.cli
gh auth login                  # elige "Login with a web browser"
cd C:\Proxy
gh repo create pxproxy --private --source=. --remote=origin --push
```

Con esto queda subido Y autenticado para futuros push/pull sin más pasos.

### Opción B — Navegador + token (si no quieres instalar nada)

1. Crea el repo vacío como en Paso 2.
2. Genera un token: <https://github.com/settings/tokens/new> → marca solo `repo` → caducidad 30 días → copia el token (se ve UNA vez; guárdalo en tu gestor de contraseñas).
3. Ejecuta:

```powershell
cd C:\Proxy
git remote add origin https://github.com/TUUSUARIO/pxproxy.git
git push -u origin main        # usuario: TUUSUARIO · contraseña: el token (no tu password)
```

## Acceder desde cualquier sitio

- **Web**: <https://github.com/TUUSUARIO/pxproxy> (código, historial, issues)
- **Clonar en otra máquina**:
  ```bash
  git clone https://github.com/TUUSUARIO/pxproxy.git
  ```
  (pedirá usuario + token; con la Opción A basta `gh auth login`)
- Los secretos runtime (`config.json`, `secrets.key`…) no están en el repo: tras clonar en una máquina nueva, copia el `config.json` real del servidor o arranca desde cero (`config.example.json` es la plantilla).

## Reglas de oro del repo

1. NUNCA fuerces la subida de: `config.json`, `secrets.key`, `audit.log*`, `backups/`, tokens o contraseñas (el `.gitignore` ya lo bloquea; no lo quites).
2. Si algún día se sube un secreto por accidente: **rotar la credencial** (cambiarla), no basta borrar el fichero — queda en el historial.
3. El token de acceso (Opción B) caduca solo si le pusiste 30 días; revócalo antes en Settings → Tokens si sospechas exposición.

## Identidad git local

El commit inicial usa identidad neutra. Para poner la tuya:

```powershell
cd C:\Proxy
git config user.name "Tu Nombre"
git config user.email "tu@email.com"
git commit --amend --reset-author --no-edit   # reescribe el autor del commit inicial
```
