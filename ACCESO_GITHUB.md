# ACCESO AL REPOSITORIO

## ✅ Estado actual (completado)

- **Repo remoto**: <https://github.com/asmarin1996-ops/pxproxy> (**PRIVADO**, rama `main`)
- Commit inicial `94b4e92` subido (40 ficheros); secretos excluidos por `.gitignore`
- Autenticación configurada vía GitHub CLI (`gh`) en este equipo — push/pull sin contraseñas

## Trabajar desde cualquier sitio

**En la web**: <https://github.com/asmarin1996-ops/pxproxy>

**Clonar en otra máquina**:
```bash
git clone https://github.com/asmarin1996-ops/pxproxy.git
```
Autenticación en esa máquina: instala GitHub CLI y ejecuta `gh auth login` (mismo flujo de código de dispositivo), o usa un token clásico con scope `repo` como contraseña.

**Flujo diario local**:
```powershell
git pull            # antes de empezar
git add -A && git commit -m "cambio"
git push
```

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
