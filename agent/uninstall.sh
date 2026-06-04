#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="wgtunnel-agent"
BINARY="$INSTALL_DIR/$SERVICE_NAME"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
WG_CONF="/etc/wireguard/wg0.conf"

if [[ $EUID -ne 0 ]]; then
  echo "ERRO: execute com sudo: sudo ./uninstall.sh"
  exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Desinstalação do WG Tunnel Agent"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── 1. Parar e desabilitar serviço ────────────────────────────────────────────
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  echo "==> Parando serviço $SERVICE_NAME..."
  systemctl stop "$SERVICE_NAME"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
  echo "==> Desabilitando serviço $SERVICE_NAME..."
  systemctl disable "$SERVICE_NAME"
fi

# ── 2. Remover arquivo de serviço ─────────────────────────────────────────────
if [[ -f "$SERVICE_FILE" ]]; then
  echo "==> Removendo $SERVICE_FILE..."
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload
fi

# ── 3. Remover binário ────────────────────────────────────────────────────────
if [[ -f "$BINARY" ]]; then
  echo "==> Removendo binário $BINARY..."
  rm -f "$BINARY"
fi

# ── 4. Derrubar e desabilitar WireGuard ───────────────────────────────────────
if systemctl is-active --quiet "wg-quick@wg0" 2>/dev/null; then
  echo "==> Derrubando interface WireGuard wg0..."
  wg-quick down wg0 2>/dev/null || true
fi

if systemctl is-enabled --quiet "wg-quick@wg0" 2>/dev/null; then
  echo "==> Desabilitando wg-quick@wg0..."
  systemctl disable "wg-quick@wg0"
fi

# ── 5. Remover configuração WireGuard ─────────────────────────────────────────
if [[ -f "$WG_CONF" ]]; then
  read -rp "Remover $WG_CONF? [s/N]: " REMOVE_WG
  REMOVE_WG="${REMOVE_WG,,}"
  if [[ "$REMOVE_WG" == "s" || "$REMOVE_WG" == "sim" ]]; then
    rm -f "$WG_CONF"
    echo "==> $WG_CONF removido."
  else
    echo "==> $WG_CONF mantido."
  fi
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✓ Desinstalação concluída!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
