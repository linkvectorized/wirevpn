#!/usr/bin/env bash
# adguard_client.sh — Update WireVPN client configs to use AdGuard Home DNS
# Run this on your Mac after running adguard_setup.sh on your VPS

set -e

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

PASS="${GREEN}[✓]${NC}"
FAIL="${RED}[✗]${NC}"

AGH_DNS="10.0.0.1"

# ── Find WireVPN directory ─────────────────────────────────────────────────────
WIREVPN_DIR=""
for candidate in \
  "$HOME/Desktop/WireVPN" \
  "$HOME/WireVPN" \
  "$HOME/Documents/WireVPN" \
  "$HOME/Downloads/WireVPN"; do
  if [ -d "$candidate" ]; then
    WIREVPN_DIR="$candidate"
    break
  fi
done
if [ -z "$WIREVPN_DIR" ]; then
  WIREVPN_DIR=$(find "$HOME" -maxdepth 4 -name "client.conf" -path "*/WireVPN/*" 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true)
fi
if [ -z "$WIREVPN_DIR" ]; then
  printf "${RED}Could not find WireVPN directory. Expected ~/Desktop/WireVPN or similar.${NC}\n"
  exit 1
fi

# ── Intro ─────────────────────────────────────────────────────────────────────
clear
printf "${CYAN}"
cat << 'EOF'
  ╔══════════════════════════════════════════════╗
  ║      WireVPN — AdGuard DNS Update            ║
  ╚══════════════════════════════════════════════╝
EOF
printf "${NC}\n"
printf "${YELLOW}  ⚠  Points your tunnel DNS at AdGuard Home — blocks ads for every device.${NC}\n\n"
sleep 1

# ── macOS only ────────────────────────────────────────────────────────────────
if [ "$(uname -s)" != "Darwin" ]; then
  printf "${RED}This script is for macOS. For Linux clients, edit your .conf DNS line manually.${NC}\n"
  exit 1
fi

# ── Check sudo ────────────────────────────────────────────────────────────────
printf "${BOLD}  This script requires sudo. You may be prompted for your password.${NC}\n\n"
sudo -v

# ── Find .conf files ──────────────────────────────────────────────────────────
printf "${BOLD}── Pre-flight check ──${NC}\n\n"

printf "1. WireVPN config files\n"
CONF_FILES=()
while IFS= read -r -d '' f; do
  CONF_FILES+=("$f")
done < <(find "$WIREVPN_DIR" -maxdepth 1 -name "*.conf" -print0 2>/dev/null)

if [ ${#CONF_FILES[@]} -eq 0 ]; then
  printf "   $FAIL No .conf files found in $WIREVPN_DIR\n\n"
  printf "   ${RED}Expected client.conf, phone.conf, etc. in ~/Desktop/WireVPN/${NC}\n"
  exit 1
fi

for f in "${CONF_FILES[@]}"; do
  CURRENT_DNS=$(grep "^DNS" "$f" 2>/dev/null | awk '{print $3}' || true)
  NAME=$(basename "$f")
  if [ "$CURRENT_DNS" = "$AGH_DNS" ]; then
    printf "   $PASS $NAME — DNS already set to $AGH_DNS\n"
  else
    printf "   ${YELLOW}→${NC} $NAME — DNS: ${CYAN}${CURRENT_DNS:-not set}${NC}\n"
  fi
done

echo ""

# 2. Tunnel status
printf "2. VPN tunnel\n"
TUNNEL_ACTIVE=false
if sudo wg show 2>/dev/null | grep -q "interface"; then
  printf "   $PASS Tunnel is active — will bounce to pick up new DNS\n"
  TUNNEL_ACTIVE=true
else
  printf "   ${YELLOW}Tunnel not active — DNS will apply on next connect${NC}\n"
fi

echo ""

# Check if anything actually needs updating
NEEDS_UPDATE=()
for f in "${CONF_FILES[@]}"; do
  CURRENT_DNS=$(grep "^DNS" "$f" 2>/dev/null | awk '{print $3}' || true)
  if [ "$CURRENT_DNS" != "$AGH_DNS" ]; then
    NEEDS_UPDATE+=("$f")
  fi
done

if [ ${#NEEDS_UPDATE[@]} -eq 0 ]; then
  printf "   ${GREEN}All configs already using AdGuard DNS ($AGH_DNS). Nothing to do.${NC}\n\n"
  if [ "$TUNNEL_ACTIVE" = true ]; then
    printf "  ${BOLD}Verify it's working:${NC}\n"
    printf "    ${CYAN}dig @$AGH_DNS doubleclick.net${NC}   # should return NXDOMAIN\n\n"
  fi
  exit 0
fi

printf "${BOLD}── Updating configs ──${NC}\n\n"

# ── Update each config file ───────────────────────────────────────────────────
for f in "${NEEDS_UPDATE[@]}"; do
  NAME=$(basename "$f")
  echo "==> $NAME"

  # Back up original
  cp "$f" "${f}.bak"
  printf "   $PASS Backed up to ${NAME}.bak\n"

  # Replace DNS line — handles both commented and active DNS lines
  if grep -q "^DNS" "$f"; then
    # Replace existing DNS line
    sed -i '' "s|^DNS = .*|DNS = $AGH_DNS|" "$f"
  elif grep -q "^# DNS" "$f"; then
    # Uncomment and set
    sed -i '' "s|^# DNS.*|DNS = $AGH_DNS|" "$f"
  else
    # No DNS line at all — add one after Address line
    sed -i '' "/^Address/a\\
DNS = $AGH_DNS" "$f"
  fi
  printf "   $PASS DNS updated to $AGH_DNS\n"

  # Install to /etc/wireguard/
  DEST="/etc/wireguard/$NAME"
  if [ -f "$DEST" ]; then
    sudo cp "$DEST" "${DEST}.bak"
    printf "   ${YELLOW}Backed up existing $DEST${NC}\n"
  fi
  sudo cp "$f" "$DEST"
  sudo chmod 600 "$DEST"
  printf "   $PASS Installed to $DEST\n\n"
done

# ── Bounce tunnel to pick up new DNS ─────────────────────────────────────────
if [ "$TUNNEL_ACTIVE" = true ]; then
  echo "==> Bouncing tunnel to apply new DNS..."
  # Use client.conf as the primary tunnel — it's always the Mac's main config
  ACTIVE_CONF="/etc/wireguard/client.conf"
  if [ -f "$ACTIVE_CONF" ]; then
    sudo wg-quick down "$ACTIVE_CONF" 2>/dev/null || true
    sleep 2
    sudo wg-quick up "$ACTIVE_CONF"
    printf "   $PASS Tunnel reconnected with AdGuard DNS\n\n"
  else
    printf "   ${YELLOW}Could not find client.conf — reconnect manually:${NC}\n"
    printf "   ${CYAN}sudo wg-quick down /etc/wireguard/client.conf${NC}\n"
    printf "   ${CYAN}sudo wg-quick up /etc/wireguard/client.conf${NC}\n\n"
  fi
else
  printf "   ${YELLOW}Tunnel was not active — new DNS will apply on next connect.${NC}\n\n"
fi

# ── Verify: blocked domain ────────────────────────────────────────────────────
echo "==> Verifying ad blocking..."
if command -v dig &>/dev/null; then
  sleep 1
  BLOCKED=$(dig @"$AGH_DNS" doubleclick.net A +short +time=5 2>/dev/null || true)
  if [ -z "$BLOCKED" ] || echo "$BLOCKED" | grep -qE "^(0\.0\.0\.0|NXDOMAIN)"; then
    printf "   $PASS doubleclick.net → blocked (${BLOCKED:-NXDOMAIN})\n"
  else
    printf "   ${YELLOW}doubleclick.net returned: $BLOCKED${NC}\n"
    printf "   ${YELLOW}AdGuard may still be loading filter lists — try again in 30s.${NC}\n"
  fi
else
  printf "   ${YELLOW}dig not installed — install via: brew install bind${NC}\n"
fi

# Verify exit IP still routes through VPS
echo ""
echo "==> Verifying exit IP..."
MY_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || true)
if [ -n "$MY_IP" ]; then
  printf "   $PASS Exit IP: ${CYAN}$MY_IP${NC}\n"
  printf "   ${YELLOW}If this matches your VPS IP, tunnel is routing correctly.${NC}\n"
else
  printf "   ${YELLOW}Could not verify exit IP — check connection and run: curl ifconfig.me${NC}\n"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
printf "${GREEN}${BOLD}"
cat << 'EOF'
  ╔══════════════════════════════════════════════╗
  ║      DNS UPDATED. ADS BLOCKED EVERYWHERE.    ║
  ╚══════════════════════════════════════════════╝
EOF
printf "${NC}\n"

printf "  ${BOLD}Web UI (while connected to VPN):${NC}\n"
printf "  ${CYAN}open http://10.0.0.1:3000${NC}\n\n"
printf "  ${BOLD}Useful commands:${NC}\n"
printf "    Verify blocking:  ${CYAN}dig @10.0.0.1 doubleclick.net${NC}\n"
printf "    Check exit IP:    ${CYAN}curl ifconfig.me${NC}\n"
printf "    Open web UI:      ${CYAN}open http://10.0.0.1:3000${NC}\n\n"
printf "${YELLOW}  Stay private. Block the noise. Question everything. Never trust your government. Stand against the machine.${NC}\n\n"
