#!/usr/bin/env bash
# add_peer.sh — Add or remove WireGuard peers on your WireVPN server
# Run this on your Mac (not the VPS)
#
# Usage:
#   bash add_peer.sh <name>           — add a new peer (shows QR code)
#   bash add_peer.sh remove <name>    — revoke a peer's access immediately
#
# Examples:
#   bash add_peer.sh phone
#   bash add_peer.sh laptop
#   bash add_peer.sh brian
#   bash add_peer.sh remove phone

set -e

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

PASS="${GREEN}[✓]${NC}"
FAIL="${RED}[✗]${NC}"

# ── Find WireVPN directory ─────────────────────────────────────────────────────
WIREVPN_DIR=""
for candidate in \
  "$HOME/Desktop/WireVPN" \
  "$HOME/WireVPN" \
  "$HOME/Documents/WireVPN" \
  "$HOME/Downloads/WireVPN"; do
  if [ -f "$candidate/client.conf" ]; then
    WIREVPN_DIR="$candidate"
    break
  fi
done

if [ -z "$WIREVPN_DIR" ]; then
  WIREVPN_DIR=$(find "$HOME" -name "client.conf" -path "*/WireVPN/*" 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true)
fi

if [ -z "$WIREVPN_DIR" ]; then
  printf "${RED}Could not find WireVPN directory with client.conf${NC}\n"
  exit 1
fi

CLIENT_CONF="$WIREVPN_DIR/client.conf"

# ── Parse args ────────────────────────────────────────────────────────────────
ACTION="add"
PEER_NAME=""

if [ "$1" = "remove" ]; then
  ACTION="remove"
  PEER_NAME="$2"
else
  PEER_NAME="$1"
fi

if [ -z "$PEER_NAME" ]; then
  printf "${BOLD}Usage:${NC}\n"
  printf "  bash add_peer.sh <name>           — add a peer\n"
  printf "  bash add_peer.sh remove <name>    — remove a peer\n\n"
  printf "Examples:\n"
  printf "  bash add_peer.sh phone\n"
  printf "  bash add_peer.sh laptop\n"
  printf "  bash add_peer.sh brian\n"
  printf "  bash add_peer.sh remove phone\n"
  exit 1
fi

# ── Read VPS IP from client.conf ──────────────────────────────────────────────
VPS_IP=$(grep "Endpoint" "$CLIENT_CONF" | awk '{print $3}' | cut -d: -f1)
if [ -z "$VPS_IP" ]; then
  printf "${RED}Could not parse VPS IP from $CLIENT_CONF${NC}\n"
  exit 1
fi

# ── Header ────────────────────────────────────────────────────────────────────
clear
printf "${CYAN}"
cat << 'EOF'
  ╔══════════════════════════════════════════════╗
  ║         WireVPN — Peer Manager               ║
  ╚══════════════════════════════════════════════╝
EOF
printf "${NC}\n"
printf "  Action : ${CYAN}$ACTION${NC}\n"
printf "  Peer   : ${CYAN}$PEER_NAME${NC}\n"
printf "  VPS    : ${CYAN}$VPS_IP${NC}\n\n"

# ── ADD ───────────────────────────────────────────────────────────────────────
if [ "$ACTION" = "add" ]; then

  if [ -f "$WIREVPN_DIR/${PEER_NAME}.conf" ]; then
    printf "${YELLOW}${PEER_NAME}.conf already exists locally. Overwrite? [y/N] ${NC}"
    read -r CONFIRM
    [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ] || { printf "Aborted.\n"; exit 0; }
  fi

  printf "==> Setting up peer on VPS...\n\n"

  ssh "root@$VPS_IP" bash -s << ENDSSH
set -e
PEER_NAME="$PEER_NAME"

# Find next available IP
LAST_OCTET=\$(grep "AllowedIPs" /etc/wireguard/wg0.conf | grep -oE '10\.0\.0\.[0-9]+' | cut -d. -f4 | sort -n | tail -1)
if [ -z "\$LAST_OCTET" ]; then
  NEXT_IP="10.0.0.2"
else
  NEXT_IP="10.0.0.\$((LAST_OCTET + 1))"
fi

# Generate keypair
PRIVATE=\$(wg genkey)
PUBLIC=\$(echo "\$PRIVATE" | wg pubkey)
SERVER_PUBLIC=\$(wg show wg0 public-key)
# Keep server_public.key in sync with reality
echo "\$SERVER_PUBLIC" > /etc/wireguard/server_public.key
SERVER_IP=\$(curl -s --max-time 5 ifconfig.me)

# Save keys to disk
printf '%s\n' "\$PRIVATE" > /etc/wireguard/\${PEER_NAME}_private.key
printf '%s\n' "\$PUBLIC"  > /etc/wireguard/\${PEER_NAME}_public.key
chmod 600 /etc/wireguard/\${PEER_NAME}_private.key

# Live-add peer (no WireGuard restart needed)
wg set wg0 peer "\$PUBLIC" allowed-ips "\${NEXT_IP}/32"

# Persist to wg0.conf
printf '\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n' "\$PEER_NAME" "\$PUBLIC" "\$NEXT_IP" >> /etc/wireguard/wg0.conf

# Write peer client config
printf '[Interface]\nPrivateKey = %s\nAddress = %s/24\nDNS = 10.0.0.1\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n' \
  "\$PRIVATE" "\$NEXT_IP" "\$SERVER_PUBLIC" "\$SERVER_IP" > /etc/wireguard/\${PEER_NAME}.conf
chmod 600 /etc/wireguard/\${PEER_NAME}.conf

echo "  Peer \$PEER_NAME added at \$NEXT_IP"
ENDSSH

  printf "\n==> Pulling config to Mac...\n"
  scp -q "root@$VPS_IP:/etc/wireguard/${PEER_NAME}.conf" "$WIREVPN_DIR/${PEER_NAME}.conf"
  printf "   $PASS Saved to $WIREVPN_DIR/${PEER_NAME}.conf\n"

  printf "\n==> Generating QR code...\n\n"
  if ! command -v qrencode &>/dev/null; then
    printf "   Installing qrencode...\n"
    brew install qrencode -q
  fi
  qrencode -t ansiutf8 < "$WIREVPN_DIR/${PEER_NAME}.conf"

  printf "\n   $PASS Scan the QR code in the WireGuard app\n"
  printf "       iOS/Android: tap + → Create from QR code\n\n"
  printf "${GREEN}${BOLD}  Peer '${PEER_NAME}' is live.${NC}\n\n"

# ── REMOVE ────────────────────────────────────────────────────────────────────
elif [ "$ACTION" = "remove" ]; then

  printf "${YELLOW}  This will immediately revoke access for '${PEER_NAME}'.${NC}\n"
  printf "  Continue? [y/N] "
  read -r CONFIRM
  [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ] || { printf "Aborted.\n"; exit 0; }

  printf "\n==> Revoking peer on VPS...\n"

  ssh "root@$VPS_IP" bash -s << ENDSSH
set -e
PEER_NAME="$PEER_NAME"

if [ ! -f /etc/wireguard/\${PEER_NAME}_public.key ]; then
  echo "ERROR: No keys found for '\$PEER_NAME' — check the name and try again"
  exit 1
fi

PUBLIC=\$(cat /etc/wireguard/\${PEER_NAME}_public.key)

# Remove from live WireGuard immediately
wg set wg0 peer "\$PUBLIC" remove

# Write Python script to cleanly remove the [Peer] block from wg0.conf
cat > /tmp/remove_peer.py << 'PYEOF'
import re, sys

peer_name = sys.argv[1]
with open('/etc/wireguard/' + peer_name + '_public.key') as f:
    pubkey = f.read().strip()

with open('/etc/wireguard/wg0.conf') as f:
    content = f.read()

sections = re.split(r'(?m)^(?=\[)', content)
sections = [s for s in sections if pubkey not in s]

with open('/etc/wireguard/wg0.conf', 'w') as f:
    f.write(''.join(sections).rstrip('\n') + '\n')

print('  Block removed from wg0.conf')
PYEOF

python3 /tmp/remove_peer.py "\$PEER_NAME"
rm -f /tmp/remove_peer.py

# Remove key files and config from server
rm -f /etc/wireguard/\${PEER_NAME}_private.key \
      /etc/wireguard/\${PEER_NAME}_public.key \
      /etc/wireguard/\${PEER_NAME}.conf

echo "  Peer \$PEER_NAME revoked"
ENDSSH

  if [ -f "$WIREVPN_DIR/${PEER_NAME}.conf" ]; then
    rm "$WIREVPN_DIR/${PEER_NAME}.conf"
    printf "   $PASS Local config removed\n"
  fi

  printf "\n${GREEN}${BOLD}  Peer '${PEER_NAME}' has been revoked.${NC}\n"
  printf "  They can no longer connect to your VPN.\n\n"

fi
