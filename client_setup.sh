#!/usr/bin/env bash
# client_setup.sh — WireGuard VPN client setup for macOS and Linux
# Run this on your machine after running server_setup.sh on your VPS

set -e

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
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

# If not found in common locations, search the whole home directory
if [ -z "$CONF_SRC" ]; then
  CONF_SRC=$(find "$HOME" -name "client.conf" -path "*/WireVPN/*" 2>/dev/null | head -1)
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
  printf "   $FAIL client.conf not found anywhere under $HOME\n\n"
  printf "   ${RED}Run these commands first, then re-run this script:${NC}\n\n"
  printf "   mkdir -p ~/WireVPN\n"
  printf "   scp root@YOUR_SERVER_IP:/etc/wireguard/client.conf ~/WireVPN/client.conf\n\n"
  exit 1
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

  if ! command -v wg &>/dev/null || ! command -v wg-quick &>/dev/null; then
    echo "==> Installing WireGuard tools..."
    brew install wireguard-tools
    printf "   $PASS WireGuard tools installed\n"
  else
    printf "   $PASS WireGuard tools already installed\n"
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

# ── 2. Install client config ───────────────────────────────────────────────────
echo ""
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
  WG_QUICK_PATH="$(which wg-quick)"

  # Install wrapper script that waits for network before connecting
  sudo mkdir -p /usr/local/bin
  sudo tee /usr/local/bin/wirevpn-connect.sh > /dev/null << EOF
#!/bin/bash
# Wait for network before starting WireGuard (up to 30s)
MAX=30
COUNT=0
until ping -c1 -W1 1.1.1.1 &>/dev/null 2>&1 || [ \$COUNT -ge \$MAX ]; do
  sleep 1
  COUNT=\$((COUNT + 1))
done

if [ \$COUNT -ge \$MAX ]; then
  echo "\$(date): Network not available after \${MAX}s — skipping WireGuard" >> /var/log/wirevpn.log
  exit 1
fi

echo "\$(date): Network ready — starting WireGuard" >> /var/log/wirevpn.log
${WG_QUICK_PATH} up ${CONF_DEST} >> /var/log/wirevpn.log 2>&1
EOF
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

# ── 4. Verify ─────────────────────────────────────────────────────────────────
echo ""
echo "==> Verifying connection..."
sleep 2
MY_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || true)
if [ -z "$MY_IP" ]; then
  printf "   ${YELLOW}Could not verify exit IP — check your connection and run: curl ifconfig.me${NC}\n"
else
  printf "   $PASS Exit IP: ${CYAN}$MY_IP${NC}\n"
  printf "   ${YELLOW}If this matches your VPS IP, you're routing through the tunnel.${NC}\n"
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
printf "${YELLOW}  Stay private. Question narratives. Build cool things.${NC}\n\n"
