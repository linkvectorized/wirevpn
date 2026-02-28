#!/usr/bin/env bash
# client_setup.sh — WireGuard VPN client setup for macOS
# Run this on your Mac after running server_setup.sh on your VPS

set -e

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

PASS="${GREEN}[✓]${NC}"
FAIL="${RED}[✗]${NC}"

CONF_PATH="$HOME/Desktop/WireVPN/client.conf"
PLIST_SRC="$HOME/Desktop/WireVPN/com.wirevpn.startup.plist"
PLIST_DEST="/Library/LaunchDaemons/com.wirevpn.startup.plist"

# ── Intro ─────────────────────────────────────────────────────────────────────
clear
printf "${CYAN}"
cat << 'EOF'
  ╔══════════════════════════════════════════════╗
  ║         WireVPN — Client Setup               ║
  ║         linkvectorized                       ║
  ╚══════════════════════════════════════════════╝
EOF
printf "${NC}\n"
printf "${YELLOW}  ⚠  Your traffic belongs to you. Not your ISP. Not big tech.${NC}\n"
printf "${YELLOW}     Route around surveillance. Stay sovereign.${NC}\n\n"
sleep 1

# ── Pre-flight check ──────────────────────────────────────────────────────────
printf "${BOLD}── Pre-flight check ──${NC}\n\n"

# 1. Homebrew
printf "1. Homebrew\n"
if command -v brew &>/dev/null; then
  printf "   $PASS installed — $(brew --version | head -1)\n"
else
  printf "   $FAIL not installed — will install\n"
fi

echo ""

# 2. WireGuard tools
printf "2. WireGuard tools\n"
if command -v wg &>/dev/null; then
  printf "   $PASS wg installed — $(which wg)\n"
else
  printf "   $FAIL wg not installed — will install\n"
fi

if command -v wg-quick &>/dev/null; then
  printf "   $PASS wg-quick installed — $(which wg-quick)\n"
else
  printf "   $FAIL wg-quick not installed — will install\n"
fi

echo ""

# 3. Client config
printf "3. Client config\n"
if [ -f "$CONF_PATH" ]; then
  printf "   $PASS client.conf found at $CONF_PATH\n"
else
  printf "   $FAIL client.conf not found at $CONF_PATH\n"
  printf "   ${RED}    You need to create client.conf before running this script.${NC}\n"
fi

echo ""

# 4. LaunchDaemon plist
printf "4. Auto-connect on startup\n"
if [ -f "$PLIST_DEST" ]; then
  printf "   $PASS launchd plist installed at $PLIST_DEST\n"
else
  printf "   $FAIL launchd plist not installed — will install\n"
fi

if sudo launchctl list | grep -q "com.wirevpn.startup" 2>/dev/null; then
  printf "   $PASS launchd daemon loaded\n"
else
  printf "   $FAIL launchd daemon not loaded — will load\n"
fi

echo ""

# 5. VPN connection
printf "5. VPN connection\n"
if ifconfig utun3 &>/dev/null 2>&1; then
  printf "   $PASS VPN tunnel active (utun3)\n"
else
  printf "   $FAIL VPN not connected — will connect\n"
fi

echo ""
printf "${BOLD}── Starting setup ──${NC}\n\n"

# ── 1. Homebrew ───────────────────────────────────────────────────────────────
if ! command -v brew &>/dev/null; then
  echo "==> Installing Homebrew..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  eval "$(/opt/homebrew/bin/brew shellenv)"
else
  printf "   $PASS Homebrew already installed\n"
  eval "$(brew shellenv)"
fi

# ── 2. WireGuard tools ────────────────────────────────────────────────────────
if ! command -v wg &>/dev/null || ! command -v wg-quick &>/dev/null; then
  echo "==> Installing WireGuard tools..."
  brew install wireguard-tools
  printf "   $PASS WireGuard tools installed\n"
else
  printf "   $PASS WireGuard tools already installed\n"
fi

# ── 3. Fix client.conf permissions ────────────────────────────────────────────
if [ -f "$CONF_PATH" ]; then
  chmod 600 "$CONF_PATH"
  printf "   $PASS client.conf permissions fixed (600)\n"
else
  printf "   ${RED}client.conf not found at $CONF_PATH — aborting.${NC}\n"
  printf "   Create your client.conf first then re-run this script.\n"
  exit 1
fi

# ── 4. Install launchd plist ──────────────────────────────────────────────────
echo ""
echo "==> Installing auto-connect daemon..."
sudo cp "$PLIST_SRC" "$PLIST_DEST"
sudo chmod 644 "$PLIST_DEST"
sudo chown root:wheel "$PLIST_DEST"

if sudo launchctl list | grep -q "com.wirevpn.startup" 2>/dev/null; then
  sudo launchctl unload "$PLIST_DEST" 2>/dev/null || true
fi
sudo launchctl load "$PLIST_DEST"
printf "   $PASS Auto-connect daemon installed and loaded\n"

# ── 5. Connect VPN ────────────────────────────────────────────────────────────
echo ""
echo "==> Connecting to VPN..."
if ifconfig utun3 &>/dev/null 2>&1; then
  printf "   $PASS VPN already connected\n"
else
  sudo wg-quick up "$CONF_PATH"
  printf "   $PASS VPN connected\n"
fi

# ── 6. Verify ─────────────────────────────────────────────────────────────────
echo ""
echo "==> Verifying connection..."
MY_IP=$(curl -s ifconfig.me)
printf "   $PASS Exit IP: ${CYAN}$MY_IP${NC}\n"
printf "   ${YELLOW}If this matches your VPS IP, you're routing through the tunnel.${NC}\n"

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
printf "    Connect:     ${CYAN}sudo wg-quick up ~/Desktop/WireVPN/client.conf${NC}\n"
printf "    Disconnect:  ${CYAN}sudo wg-quick down ~/Desktop/WireVPN/client.conf${NC}\n"
printf "    Check IP:    ${CYAN}curl ifconfig.me${NC}\n"
printf "    VPN logs:    ${CYAN}cat /var/log/wirevpn.log${NC}\n"
printf "    VPN status:  ${CYAN}sudo wg show${NC}\n"
echo ""
printf "${YELLOW}  Stay private. Question narratives. Build cool things.${NC}\n\n"
