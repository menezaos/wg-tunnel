#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="wgtunnel-agent"
BINARY="$INSTALL_DIR/$SERVICE_NAME"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"

echo "==> Compilando wgtunnel-agent..."
cd "$(dirname "$0")"

if ! command -v go &>/dev/null; then
  echo "==> Go não encontrado. Instalando..."
  GO_VERSION="1.22.4"
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)  GO_ARCH="amd64" ;;
    aarch64) GO_ARCH="arm64" ;;
    armv7l)  GO_ARCH="armv6l" ;;
    *)       echo "ERRO: arquitetura $ARCH não suportada"; exit 1 ;;
  esac
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tar.gz
  rm /tmp/go.tar.gz
  export PATH="$PATH:/usr/local/go/bin"
  echo "==> Go ${GO_VERSION} instalado."
fi

go build -ldflags="-s -w" -o "$SERVICE_NAME" .

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
