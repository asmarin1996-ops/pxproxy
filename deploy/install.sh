#!/usr/bin/env bash
# Instalador de PxProxy para Ubuntu Server 22.04/24.04
# Uso: sudo ./install.sh [binario]   (por defecto dist/pxproxy-linux-amd64)
set -euo pipefail

BIN="${1:-dist/pxproxy-linux-amd64}"
SERVICE_NAME="pxproxy"

if [ "$(id -u)" -ne 0 ]; then echo "Ejecuta con sudo"; exit 1; fi
if [ ! -f "$BIN" ]; then echo "No existe el binario $BIN (compila con: make linux)"; exit 1; fi

echo "== usuario de servicio =="
id -u "$SERVICE_NAME" &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_NAME"

echo "== directorios =="
install -d -o "$SERVICE_NAME" -g "$SERVICE_NAME" -m 750 /var/lib/pxproxy /etc/pxproxy
mkdir -p /var/lib/pxproxy/{certs,backups,acme-cache}
chown -R "$SERVICE_NAME:$SERVICE_NAME" /var/lib/pxproxy

echo "== binario =="
install -m 755 "$BIN" /usr/local/bin/pxproxy

echo "== unidad systemd =="
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/pxproxy.service" ]; then
  install -m 644 "$SCRIPT_DIR/pxproxy.service" /etc/systemd/system/${SERVICE_NAME}.service
elif [ -f ./pxproxy.service ]; then
  install -m 644 ./pxproxy.service /etc/systemd/system/${SERVICE_NAME}.service
else
  echo "No se encontro pxproxy.service junto al instalador"; exit 1
fi
systemctl daemon-reload

echo "== firewall (opcional) =="
if command -v ufw &>/dev/null; then
  ufw allow 80/tcp 2>/dev/null || true
  ufw allow 443/tcp 2>/dev/null || true
  ufw allow 8000/tcp 2>/dev/null || true
fi

systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}
sleep 1
systemctl --no-pager status ${SERVICE_NAME} | head -n 12

cat <<'EOF'

INSTALACION COMPLETA
  Configuracion : /etc/pxproxy/config.json   (credenciales por defecto: admin / Admin123!)
  Datos         : /var/lib/pxproxy           (certs/, backups/, audit.log)
  Panel         : http://<IP>:8000           (cambia la contrasena YA)

Comandos utiles:
  systemctl status|restart|stop pxproxy
  journalctl -u pxproxy -f
EOF
