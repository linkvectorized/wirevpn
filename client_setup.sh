#!/usr/bin/env bash
# client_setup.sh — WireGuard VPN client setup for macOS and Linux
# Run this on your machine after running server_setup.sh on your VPS

set -e

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
BOLD_RED_UL=$'\033[1;4;31m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

PASS="${GREEN}[✓]${NC}"
FAIL="${RED}[✗]${NC}"

CONF_DEST="/etc/wireguard/client.conf"

# ── Find client.conf ──────────────────────────────────────────────────────────
# Search common locations, then fall back to a full user directory search
CONF_SRC=""
for candidate in \
  "$HOME/WireVPN/client.conf" \
  "$HOME/Desktop/WireVPN/client.conf" \
  "$HOME/Documents/WireVPN/client.conf" \
  "$HOME/Downloads/WireVPN/client.conf"; do
  if [ -f "$candidate" ]; then
    CONF_SRC="$candidate"
    break
  fi
done

# If not found in common locations, search home directory (limited depth to avoid hanging)
if [ -z "$CONF_SRC" ]; then
  CONF_SRC=$(find "$HOME" -maxdepth 4 -name "client.conf" -path "*/WireVPN/*" 2>/dev/null | head -1)
fi

# ── Detect OS ─────────────────────────────────────────────────────────────────
OS=$(uname -s)
if [ "$OS" = "Darwin" ]; then
  PLATFORM="macos"
  PLIST_DEST="/Library/LaunchDaemons/com.wirevpn.startup.plist"
elif [ "$OS" = "Linux" ]; then
  PLATFORM="linux"
  if ! command -v systemctl &>/dev/null; then
    printf "${RED}systemd not found — only systemd-based Linux distros are supported.${NC}\n"
    exit 1
  fi
  if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
  elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
  elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
  else
    printf "${RED}Unsupported Linux distro — no apt, dnf, or pacman found.${NC}\n"
    exit 1
  fi
else
  printf "${RED}Unsupported OS: $OS${NC}\n"
  exit 1
fi

# ── Intro ─────────────────────────────────────────────────────────────────────
clear
printf "${CYAN}"
cat << 'EOF'
  ╔══════════════════════════════════════════════╗
  ║         WireVPN — Client Setup               ║
  ╚══════════════════════════════════════════════╝
EOF
printf "${NC}\n"
printf "${YELLOW}  ⚠  Your traffic belongs to you. Not your ISP. Not big tech.${NC}\n"
printf "${YELLOW}     Route around surveillance. Stay sovereign.${NC}\n\n"
printf "  Platform detected: ${CYAN}$PLATFORM${NC}\n\n"
sleep 1

# ── Check sudo ────────────────────────────────────────────────────────────────
printf "${BOLD}  This script requires sudo. You may be prompted for your password.${NC}\n\n"
sudo -v

# ── Pre-flight check ──────────────────────────────────────────────────────────
printf "${BOLD}── Pre-flight check ──${NC}\n\n"

# 1. Package manager
printf "1. Package manager\n"
if [ "$PLATFORM" = "macos" ]; then
  if command -v brew &>/dev/null; then
    printf "   $PASS homebrew installed\n"
  else
    printf "   $FAIL homebrew not installed — will install\n"
  fi
else
  printf "   $PASS $PKG_MGR detected\n"
fi

echo ""

# 2. WireGuard
printf "2. WireGuard tools\n"
if command -v wg &>/dev/null; then
  printf "   $PASS wg installed\n"
else
  printf "   $FAIL wg not installed — will install\n"
fi
if command -v wg-quick &>/dev/null; then
  printf "   $PASS wg-quick installed\n"
else
  printf "   $FAIL wg-quick not installed — will install\n"
fi

echo ""

# 3. Client config
printf "3. Client config\n"
if [ -n "$CONF_SRC" ] && [ -f "$CONF_SRC" ]; then
  printf "   $PASS client.conf found at $CONF_SRC\n"
else
  printf "   $FAIL client.conf not found — will register this device with your VPS\n"
fi

echo ""

# 4. Auto-start
printf "4. Auto-connect on startup\n"
if [ "$PLATFORM" = "macos" ]; then
  if [ -f "$PLIST_DEST" ]; then
    printf "   $PASS launchd plist installed\n"
  else
    printf "   $FAIL launchd plist not installed — will install\n"
  fi
else
  if systemctl is-enabled wg-quick@client &>/dev/null 2>&1; then
    printf "   $PASS systemd service enabled\n"
  else
    printf "   $FAIL systemd service not enabled — will install\n"
  fi
fi

echo ""

# 5. VPN connection
printf "5. VPN connection\n"
if sudo wg show 2>/dev/null | grep -q "interface"; then
  printf "   $PASS VPN tunnel already active\n"
else
  printf "   $FAIL VPN not connected — will connect\n"
fi

echo ""
printf "${BOLD}── Starting setup ──${NC}\n\n"

# ── 1. Install WireGuard ──────────────────────────────────────────────────────
if [ "$PLATFORM" = "macos" ]; then
  if ! command -v brew &>/dev/null; then
    echo "==> Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  fi
  eval "$(/opt/homebrew/bin/brew shellenv)" 2>/dev/null || true
  # Fallback if brew isn't in PATH yet after install
  if ! command -v brew &>/dev/null; then
    export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
  fi

  if ! command -v wg &>/dev/null || ! command -v wg-quick &>/dev/null; then
    echo "==> Installing WireGuard tools..."
    brew install wireguard-tools
    eval "$(/opt/homebrew/bin/brew shellenv)" 2>/dev/null || true
    if ! command -v wg &>/dev/null; then
      printf "${RED}WireGuard tools install failed. Try manually: brew install wireguard-tools${NC}\n"
      exit 1
    fi
    printf "   $PASS WireGuard tools installed\n"
  else
    printf "   $PASS WireGuard tools already installed\n"
  fi

  # macOS ships bash 3.2 but wg-quick requires bash 4+ — patch shebang to use Homebrew bash
  # Resolve symlink first — sed -i won't work on symlinks, needs the real file
  WG_QUICK_BIN="$(which wg-quick 2>/dev/null || echo /opt/homebrew/bin/wg-quick)"
  # Resolve symlink — macOS readlink doesn't support -f, so follow one level manually
  WG_QUICK_REAL="$WG_QUICK_BIN"
  if [ -L "$WG_QUICK_BIN" ]; then
    TARGET=$(readlink "$WG_QUICK_BIN")
    case "$TARGET" in
      /*) WG_QUICK_REAL="$TARGET" ;;
      *)  WG_QUICK_REAL="$(dirname "$WG_QUICK_BIN")/$TARGET" ;;
    esac
  fi
  # Use brew --prefix so the path is correct on both Apple Silicon (/opt/homebrew) and Intel (/usr/local)
  BREW_BASH="$(brew --prefix)/bin/bash"
  if head -1 "$WG_QUICK_REAL" 2>/dev/null | grep -q '#!/usr/bin/env bash'; then
    sudo sed -i '' "1s|#!/usr/bin/env bash|#!${BREW_BASH}|" "$WG_QUICK_REAL"
    printf "   $PASS wg-quick patched to use bash 5 (fixes macOS bash 3.2 version error)\n"
  fi

else
  if ! command -v wg &>/dev/null || ! command -v wg-quick &>/dev/null; then
    echo "==> Installing WireGuard..."
    case "$PKG_MGR" in
      apt)
        sudo apt-get update -qq
        sudo apt-get install -y -qq wireguard
        ;;
      dnf)
        sudo dnf install -y wireguard-tools
        ;;
      pacman)
        sudo pacman -Sy --noconfirm wireguard-tools
        ;;
    esac
    printf "   $PASS WireGuard installed\n"
  else
    printf "   $PASS WireGuard already installed\n"
  fi
fi

# ── 2. Register with VPS or install existing config ───────────────────────────
echo ""
if [ -z "$CONF_SRC" ]; then
  echo "==> Registering this device with your VPS..."
  printf "  Enter your VPS IP: "
  read -r VPS_IP
  printf "  Enter a name for this device (e.g. laptop, macbook): "
  read -r DEVICE_NAME

  if [ -z "$VPS_IP" ] || [ -z "$DEVICE_NAME" ]; then
    printf "${RED}VPS IP and device name are required.${NC}\n"
    exit 1
  fi

  printf "\n  Verifying SSH access...\n"
  if ! ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "root@$VPS_IP" true 2>/dev/null; then
    printf "${RED}Cannot connect to root@$VPS_IP — check your VPS IP and SSH access.${NC}\n"
    exit 1
  fi
  printf "   $PASS SSH confirmed\n\n"

  # shellcheck disable=SC2087
  # DEVICE_NAME and VPS_IP expand locally; all server-side variables use \$ to expand remotely.
  ssh "root@$VPS_IP" bash -s << ENDSSH
set -e
PEER_NAME="$DEVICE_NAME"

LAST_OCTET=\$(grep "^AllowedIPs" /etc/wireguard/wg0.conf | grep -oE '10\.0\.0\.[0-9]+' | cut -d. -f4 | sort -n | tail -1)
if [ -z "\$LAST_OCTET" ]; then
  NEXT_IP="10.0.0.2"
else
  NEXT_IP="10.0.0.\$((LAST_OCTET + 1))"
fi

PRIVATE=\$(wg genkey)
PUBLIC=\$(echo "\$PRIVATE" | wg pubkey)
SERVER_PUBLIC=\$(wg show wg0 public-key)
echo "\$SERVER_PUBLIC" > /etc/wireguard/server_public.key
SERVER_IP=\$(curl -s --max-time 10 ifconfig.me 2>/dev/null || true)
if [ -z "\$SERVER_IP" ]; then
  echo "ERROR: Could not detect server public IP — check network connectivity"
  exit 1
fi

printf '%s\n' "\$PRIVATE" > /etc/wireguard/\${PEER_NAME}_private.key
printf '%s\n' "\$PUBLIC"  > /etc/wireguard/\${PEER_NAME}_public.key
chmod 600 /etc/wireguard/\${PEER_NAME}_private.key

wg set wg0 peer "\$PUBLIC" allowed-ips "\${NEXT_IP}/32"
printf '\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n' "\$PEER_NAME" "\$PUBLIC" "\$NEXT_IP" >> /etc/wireguard/wg0.conf

printf '[Interface]\nPrivateKey = %s\nAddress = %s/24\nDNS = 10.0.0.1\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n' \
  "\$PRIVATE" "\$NEXT_IP" "\$SERVER_PUBLIC" "\$SERVER_IP" > /etc/wireguard/\${PEER_NAME}.conf
chmod 600 /etc/wireguard/\${PEER_NAME}.conf

echo "  Device \$PEER_NAME registered at \$NEXT_IP"
ENDSSH

  mkdir -p "$HOME/WireVPN"
  scp -q "root@$VPS_IP:/etc/wireguard/${DEVICE_NAME}.conf" "$HOME/WireVPN/client.conf"
  CONF_SRC="$HOME/WireVPN/client.conf"
  printf "   $PASS Config saved to $HOME/WireVPN/client.conf\n"
fi

echo "==> Installing client config..."
sudo mkdir -p /etc/wireguard
# Back up existing config if present
if [ -f "$CONF_DEST" ]; then
  sudo cp "$CONF_DEST" "${CONF_DEST}.bak"
  printf "   ${YELLOW}Existing client.conf backed up to client.conf.bak${NC}\n"
fi
sudo cp "$CONF_SRC" "$CONF_DEST"
sudo chmod 600 "$CONF_DEST"
printf "   $PASS client.conf installed to $CONF_DEST\n"

# ── 3. Install auto-start ─────────────────────────────────────────────────────
echo ""
echo "==> Installing auto-connect on startup..."

if [ "$PLATFORM" = "macos" ]; then
  # Resolve wg-quick path — 'which' fails on macOS after brew install until shell reloads
  WG_QUICK_PATH="$(which wg-quick 2>/dev/null || true)"
  if [ -z "$WG_QUICK_PATH" ]; then
    for p in /opt/homebrew/bin/wg-quick /usr/local/bin/wg-quick; do
      [ -f "$p" ] && { WG_QUICK_PATH="$p"; break; }
    done
  fi
  if [ -z "$WG_QUICK_PATH" ]; then
    printf "${RED}wg-quick not found. Try: brew install wireguard-tools${NC}\n"
    exit 1
  fi

  # Ensure log file exists so launchd can write to it
  sudo touch /var/log/wirevpn.log
  sudo chmod 644 /var/log/wirevpn.log

  # Install wrapper script — handles DNS safety, health checks, and clean shutdown
  sudo mkdir -p /usr/local/bin
  sudo tee /usr/local/bin/wirevpn-connect.sh > /dev/null << 'EOFSCRIPT'
#!/bin/bash
# WireVPN boot connector — brings up tunnel, verifies DNS, stays resident for clean shutdown
LOG=/var/log/wirevpn.log
CONF=/etc/wireguard/client.conf
VPN_DNS="10.0.0.1"

log() { echo "$(date): $1" >> "$LOG"; }

# ── Find wg-quick (PATH may be limited under launchd) ──
WG_QUICK=""
for p in /opt/homebrew/bin/wg-quick /usr/local/bin/wg-quick; do
    [ -x "$p" ] && { WG_QUICK="$p"; break; }
done
if [ -z "$WG_QUICK" ]; then
    log "FATAL: wg-quick not found"
    exit 1
fi

# ── Detect active network interface ──
detect_iface() {
    for svc in "Wi-Fi" "Ethernet" "USB 10/100/1000 LAN"; do
        if networksetup -getinfo "$svc" 2>/dev/null | grep -q "^IP address:"; then
            echo "$svc"
            return
        fi
    done
    echo "Wi-Fi"
}

# ── Phase 1: Clean stale VPN DNS from previous crash/hard reboot ──
ACTIVE_IFACE=$(detect_iface)
CURRENT_DNS=$(networksetup -getdnsservers "$ACTIVE_IFACE" 2>/dev/null | tr '\n' ' ')

if echo "$CURRENT_DNS" | grep -qF "$VPN_DNS"; then
    log "Stale VPN DNS detected ($CURRENT_DNS on $ACTIVE_IFACE) — resetting to DHCP"
    networksetup -setdnsservers "$ACTIVE_IFACE" empty
    dscacheutil -flushcache 2>/dev/null
    killall -HUP mDNSResponder 2>/dev/null
fi

# ── Phase 2: Wait for network (up to 30s) ──
MAX=30; COUNT=0
until ping -c1 -t1 1.1.1.1 &>/dev/null || [ $COUNT -ge $MAX ]; do
    sleep 1; COUNT=$((COUNT + 1))
done

if [ $COUNT -ge $MAX ]; then
    log "Network not available after ${MAX}s — skipping WireGuard"
    exit 1
fi

# ── Shutdown handler (launchd sends SIGTERM during system shutdown) ──
cleanup() {
    log "Shutdown signal received — tearing down tunnel"
    $WG_QUICK down "$CONF" >> "$LOG" 2>&1
    ACTIVE_IFACE=$(detect_iface)
    if networksetup -getdnsservers "$ACTIVE_IFACE" 2>/dev/null | grep -qF "$VPN_DNS"; then
        networksetup -setdnsservers "$ACTIVE_IFACE" empty
        log "Force-cleared stale DNS after tunnel teardown"
    fi
    exit 0
}
trap cleanup SIGTERM SIGINT

# ── Phase 3: Bring tunnel up ──
log "Network ready — starting WireGuard"
if ! $WG_QUICK up "$CONF" >> "$LOG" 2>&1; then
    log "wg-quick up failed — ensuring DNS is clean"
    networksetup -setdnsservers "$(detect_iface)" empty
    exit 1
fi

# ── Phase 4: Verify DNS through tunnel (3 attempts, 3s timeout each) ──
DNS_OK=false
for attempt in 1 2 3; do
    if /usr/bin/dig +short +time=3 +tries=1 @${VPN_DNS} google.com 2>/dev/null | grep -qE '^[0-9]+\.'; then
        DNS_OK=true
        break
    fi
    sleep 2
done

if [ "$DNS_OK" = false ]; then
    log "DNS health check FAILED — ${VPN_DNS} not responding after 3 attempts"
    log "Tearing down tunnel to restore system DNS"
    $WG_QUICK down "$CONF" >> "$LOG" 2>&1
    networksetup -setdnsservers "$(detect_iface)" empty
    dscacheutil -flushcache 2>/dev/null
    killall -HUP mDNSResponder 2>/dev/null
    log "DNS restored to DHCP — network functional without VPN"
    exit 1
fi

log "Tunnel UP — DNS verified through ${VPN_DNS} — VPN operational"

# ── Phase 5: Stay resident to catch shutdown signals ──
# launchd sends SIGTERM during system shutdown; our trap handles clean teardown
while true; do sleep 86400; done
EOFSCRIPT
  sudo chmod 755 /usr/local/bin/wirevpn-connect.sh

  sudo tee "$PLIST_DEST" > /dev/null << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wirevpn.startup</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/wirevpn-connect.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/var/log/wirevpn.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/wirevpn.log</string>
</dict>
</plist>
EOF
  sudo chmod 644 "$PLIST_DEST"
  sudo chown root:wheel "$PLIST_DEST"
  if sudo launchctl list | grep -q "com.wirevpn.startup" 2>/dev/null; then
    sudo launchctl unload "$PLIST_DEST" 2>/dev/null || printf "   ${YELLOW}Warning: could not unload old daemon${NC}\n"
  fi
  sudo launchctl load "$PLIST_DEST"
  printf "   $PASS launchd daemon installed and loaded\n"
  printf "   $PASS Network-wait wrapper installed at /usr/local/bin/wirevpn-connect.sh\n"

else
  # Enable network-online.target so systemd waits for network before starting WireGuard
  sudo systemctl enable systemd-networkd-wait-online.service 2>/dev/null || true
  if ! sudo systemctl enable wg-quick@client; then
    printf "${RED}Failed to enable systemd service.${NC}\n"
    exit 1
  fi
  if ! sudo systemctl start wg-quick@client; then
    printf "${RED}Failed to start WireGuard. Check: sudo journalctl -u wg-quick@client${NC}\n"
    exit 1
  fi
  printf "   $PASS systemd service enabled and started (waits for network-online.target)\n"
fi

# ── 4. Bring tunnel up immediately (daemon handles future boots; this handles now) ──
printf "==> Bringing tunnel up now...\n"
if [ "$PLATFORM" = "macos" ]; then
  sudo wg-quick up /etc/wireguard/client.conf
  sleep 2
else
  sudo wg-quick up /etc/wireguard/client.conf
  sleep 2
fi

# ── 5. Verify ─────────────────────────────────────────────────────────────────
echo ""
echo "==> Verifying connection..."
sleep 2
MY_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || true)
if [ -z "$MY_IP" ]; then
  printf "   ${YELLOW}Could not verify exit IP — check your connection and run: curl ifconfig.me${NC}\n"
else
  printf "   $PASS Exit IP: ${CYAN}$MY_IP${NC}\n"
  printf "   ${BOLD_RED_UL}If this matches your VPS IP, you're routing through the tunnel.${NC}\n"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
printf "${GREEN}${BOLD}"
cat << 'EOF'
  ╔══════════════════════════════════════════════╗
  ║      TUNNEL LIVE. YOU'RE SOVEREIGN NOW.      ║
  ╚══════════════════════════════════════════════╝
EOF
printf "${NC}\n"

printf "  ${BOLD}Useful commands:${NC}\n"
printf "    Connect:     ${CYAN}sudo wg-quick up /etc/wireguard/client.conf${NC}\n"
printf "    Disconnect:  ${CYAN}sudo wg-quick down /etc/wireguard/client.conf${NC}\n"
printf "    Check IP:    ${CYAN}curl ifconfig.me${NC}\n"
printf "    VPN status:  ${CYAN}sudo wg show${NC}\n"
if [ "$PLATFORM" = "macos" ]; then
  printf "    VPN logs:    ${CYAN}cat /var/log/wirevpn.log${NC}\n"
else
  printf "    VPN logs:    ${CYAN}sudo journalctl -u wg-quick@client${NC}\n"
fi
echo ""
printf "${YELLOW}  Stay private. Question narratives. Build cool things. Never trust your government. Stand against the machine.${NC}\n\n"
