#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="wgtunnel-agent"
BINARY="$INSTALL_DIR/$SERVICE_NAME"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"

echo "==> Compilando wgtunnel-agent..."
cd "$(dirname "$0")"

if command -v go &>/dev/null; then
  go build -ldflags="-s -w" -o "$SERVICE_NAME" .
else
  echo "ERRO: Go não encontrado. Instale: https://go.dev/dl/"
  exit 1
fi

echo "==> Instalando binário em $BINARY..."
install -m 755 "$SERVICE_NAME" "$BINARY"
rm -f "$SERVICE_NAME"

echo "==> Instalando serviço systemd..."
cp wgtunnel-agent.service "$SERVICE_FILE"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo ""
echo "✓ Instalação concluída!"
echo ""
echo "Próximos passos:"
echo "  1. Copie o .conf gerado no painel para /etc/wireguard/wg0.conf"
echo "  2. systemctl start wgtunnel-agent"
echo "  3. systemctl status wgtunnel-agent"
echo ""
echo "Para expor um processo (ex: servidor DayZ):"
echo "  wgtunnel-agent expose \$(pgrep DayZServer)"
