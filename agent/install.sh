#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="wgtunnel-agent"
BINARY="$INSTALL_DIR/$SERVICE_NAME"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
WG_CONF="/etc/wireguard/wg0.conf"

if [[ $EUID -ne 0 ]]; then
  echo "ERRO: execute com sudo: sudo ./install.sh"
  exit 1
fi

cd "$(dirname "$0")"

# ── 1. Dependências ────────────────────────────────────────────────────────────
echo "==> Instalando dependências do sistema..."
if command -v apt-get &>/dev/null; then
  apt-get update -qq
  apt-get install -y wireguard-tools curl openresolv || apt-get install -y wireguard-tools curl resolvconf
fi

mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# ── 2. Go ──────────────────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
  echo "==> Go não encontrado. Instalando via apt..."
  if command -v apt-get &>/dev/null; then
    apt-get install -y golang-go
  else
    GO_VERSION="1.22.4"
    ARCH=$(uname -m)
    case "$ARCH" in
      x86_64)  GO_ARCH="amd64" ;;
      aarch64) GO_ARCH="arm64" ;;
      armv7l)  GO_ARCH="armv6l" ;;
      *) echo "ERRO: arquitetura $ARCH não suportada"; exit 1 ;;
    esac
    echo "==> Baixando Go ${GO_VERSION}..."
    curl -fL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz --exclude='go/test' --exclude='go/doc'
    rm /tmp/go.tar.gz
    export PATH="$PATH:/usr/local/go/bin"
  fi
fi

# garante que o go do apt também está no PATH
export PATH="$PATH:/usr/local/go/bin"

# ── 3. Compilar e instalar binário ─────────────────────────────────────────────
echo "==> Compilando wgtunnel-agent..."
go build -ldflags="-s -w" -o "$SERVICE_NAME" .
install -m 755 "$SERVICE_NAME" "$BINARY"
rm -f "$SERVICE_NAME"
echo "==> Binário instalado em $BINARY"

# ── 4. Configuração interativa ─────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Configuração do WG Tunnel Agent"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -rp "URL do servidor WG Tunnel (ex: http://1.2.3.4:8080): " SERVER_URL
read -rp "Token do peer (gerado no painel): " AGENT_TOKEN

# ── 5. WireGuard config ────────────────────────────────────────────────────────
if [[ -f "$WG_CONF" ]]; then
  echo ""
  echo "==> Arquivo $WG_CONF já existe."
  read -rp "Substituir pelo novo conteúdo? [s/N]: " REPLACE_WG
  REPLACE_WG="${REPLACE_WG,,}"
else
  REPLACE_WG="s"
fi

if [[ "$REPLACE_WG" == "s" || "$REPLACE_WG" == "sim" ]]; then
  echo ""
  echo "Cole o conteúdo do arquivo .conf gerado no painel."
  echo "Quando terminar, pressione Enter numa linha vazia e depois Ctrl+D:"
  echo ""
  WG_CONTENT=$(cat)
  echo "$WG_CONTENT" > "$WG_CONF"
  chmod 600 "$WG_CONF"
  echo "==> $WG_CONF salvo."
fi

# ── 6. Subir WireGuard ─────────────────────────────────────────────────────────
echo ""
echo "==> Ativando interface WireGuard wg0..."
systemctl enable wg-quick@wg0 2>/dev/null || true
wg-quick down wg0 2>/dev/null || true
wg-quick up wg0

# ── 7. Instalar serviço ────────────────────────────────────────────────────────
echo "==> Instalando serviço systemd..."
sed \
  -e "s|Environment=SERVER_URL=.*|Environment=SERVER_URL=${SERVER_URL}|" \
  -e "s|Environment=AGENT_TOKEN=.*|Environment=AGENT_TOKEN=${AGENT_TOKEN}|" \
  wgtunnel-agent.service > "$SERVICE_FILE"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# ── 8. Status final ────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✓ Instalação concluída!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
systemctl status "$SERVICE_NAME" --no-pager -l || true
echo ""
echo "Para expor um processo (ex: servidor DayZ):"
echo "  wgtunnel-agent expose \$(pgrep DayZServer)"
