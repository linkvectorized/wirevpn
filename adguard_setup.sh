#!/usr/bin/env bash
# adguard_setup.sh — DNS-level ad/tracker blocking via AdGuard Home
# Run this on your WireVPN VPS as root — after server_setup.sh

set -e

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

PASS="${GREEN}[✓]${NC}"
FAIL="${RED}[✗]${NC}"

AGH_DIR="/opt/AdGuardHome"
AGH_BIN="$AGH_DIR/AdGuardHome"
AGH_CONF="$AGH_DIR/AdGuardHome.yaml"
AGH_USER="admin"
AGH_PASS=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)

# ── Intro ─────────────────────────────────────────────────────────────────────
clear
printf "${CYAN}"
cat << 'EOF'
  ╔══════════════════════════════════════════════╗
  ║      WireVPN — AdGuard Home Setup            ║
  ╚══════════════════════════════════════════════╝
EOF
printf "${NC}\n"
printf "${YELLOW}  ⚠  Block ads and trackers at the DNS level — for every device on your tunnel.${NC}\n\n"
sleep 1

# ── Check root ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  printf "${RED}Run this as root.${NC}\n"
  exit 1
fi

# ── Pre-flight check ──────────────────────────────────────────────────────────
printf "${BOLD}── Pre-flight check ──${NC}\n\n"

# 1. WireGuard active
printf "1. WireGuard tunnel\n"
if wg show 2>/dev/null | grep -q "interface"; then
  printf "   $PASS wg0 is active\n"
else
  printf "   $FAIL WireGuard (wg0) is not running — run server_setup.sh first\n"
  exit 1
fi

echo ""

# 2. Detect architecture
printf "2. System architecture\n"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)   AGH_ARCH="amd64" ;;
  aarch64)  AGH_ARCH="arm64" ;;
  armv7l)   AGH_ARCH="armv7" ;;
  *)
    printf "   $FAIL Unsupported architecture: $ARCH\n"
    exit 1
    ;;
esac
printf "   $PASS Architecture: ${CYAN}$ARCH${NC} → using AdGuard build ${CYAN}linux_$AGH_ARCH${NC}\n"

echo ""

# 3. AdGuard already installed?
printf "3. AdGuard Home\n"
if [ -f "$AGH_BIN" ]; then
  printf "   ${YELLOW}Already installed at $AGH_DIR — will overwrite${NC}\n"
else
  printf "   $FAIL Not installed — will install\n"
fi

echo ""

# 4. Port 53 in use?
printf "4. Port 53 availability\n"
if ss -ulnp 2>/dev/null | grep -q ':53 '; then
  HOLDER=$(ss -ulnp | grep ':53 ' | awk '{print $NF}' | head -1)
  printf "   ${YELLOW}Port 53/udp is in use by: $HOLDER${NC}\n"
  printf "   ${YELLOW}Will stop systemd-resolved if needed.${NC}\n"
else
  printf "   $PASS Port 53 is free\n"
fi

echo ""
printf "${BOLD}── Starting install ──${NC}\n\n"

# ── Free port 53 if systemd-resolved is using it ──────────────────────────────
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  echo "==> Disabling systemd-resolved (conflicts with port 53)..."
  systemctl stop systemd-resolved
  systemctl disable systemd-resolved
  # Point /etc/resolv.conf at a real upstream so the server keeps working
  echo "nameserver 1.1.1.1" > /etc/resolv.conf
  printf "   $PASS systemd-resolved stopped, resolv.conf set to 1.1.1.1\n\n"
fi

# ── Download AdGuard Home ─────────────────────────────────────────────────────
echo "==> Downloading AdGuard Home (linux_$AGH_ARCH)..."
TMP_DIR=$(mktemp -d)
AGH_URL="https://static.adguard.com/adguardhome/release/AdGuardHome_linux_${AGH_ARCH}.tar.gz"
if ! curl -fsSL --max-time 120 "$AGH_URL" -o "$TMP_DIR/agh.tar.gz"; then
  printf "${RED}Download failed. Check your internet connection.${NC}\n"
  rm -rf "$TMP_DIR"
  exit 1
fi
printf "   $PASS Downloaded\n\n"

# ── Install binary ────────────────────────────────────────────────────────────
echo "==> Installing to $AGH_DIR..."
if systemctl is-active --quiet AdGuardHome 2>/dev/null; then
  systemctl stop AdGuardHome
fi
mkdir -p "$AGH_DIR"
tar -xzf "$TMP_DIR/agh.tar.gz" -C "$TMP_DIR"
cp "$TMP_DIR/AdGuardHome/AdGuardHome" "$AGH_BIN"
chmod 755 "$AGH_BIN"
rm -rf "$TMP_DIR"
printf "   $PASS Binary installed at $AGH_BIN\n\n"

# ── Register systemd service ──────────────────────────────────────────────────
echo "==> Registering AdGuardHome as a systemd service..."
if ! systemctl is-enabled AdGuardHome &>/dev/null 2>&1; then
  "$AGH_BIN" -s install
fi
printf "   $PASS Service registered\n\n"

# ── Fresh install vs re-run ───────────────────────────────────────────────────
if [ -f "$AGH_CONF" ]; then
  # Config exists — preserve it, just restart with the new binary
  echo "==> Existing config found — preserving settings and password..."
  systemctl restart AdGuardHome
  sleep 3
  if ! systemctl is-active --quiet AdGuardHome; then
    printf "${RED}AdGuardHome failed to restart. Check: journalctl -u AdGuardHome${NC}\n"
    exit 1
  fi
  printf "   $PASS AdGuard Home restarted with existing config\n"
  printf "   ${YELLOW}Password and blocklists unchanged — manage via http://10.0.0.1:3000${NC}\n\n"
  FRESH_INSTALL=false
else
  # No config — run full setup via install API
  FRESH_INSTALL=true

  echo "==> Starting AdGuard Home (setup mode)..."
  systemctl restart AdGuardHome
  sleep 3

  # Wait for setup API to become available
  printf "   Waiting for setup API"
  for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:3000/control/install/get_addresses >/dev/null 2>&1; then
      printf "\n   $PASS Setup API ready\n\n"
      break
    fi
    if [ "$i" -eq 30 ]; then
      printf "\n   ${RED}Setup API not available after 30s. Check: journalctl -u AdGuardHome${NC}\n"
      exit 1
    fi
    printf "."
    sleep 1
  done

  # ── Configure via install API ───────────────────────────────────────────────
  echo "==> Configuring AdGuard Home..."
  SETUP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:3000/control/install/configure \
    -H "Content-Type: application/json" \
    -d "{\"web\":{\"ip\":\"0.0.0.0\",\"port\":3000},\"dns\":{\"ip\":\"0.0.0.0\",\"port\":53},\"username\":\"${AGH_USER}\",\"password\":\"${AGH_PASS}\"}")
  if [ "$SETUP_CODE" != "200" ]; then
    printf "${RED}Setup API call failed (HTTP $SETUP_CODE). Check: journalctl -u AdGuardHome${NC}\n"
    exit 1
  fi
  printf "   $PASS Initial setup complete\n"

  # AGH restarts itself after configure — wait for it to come back
  printf "   Waiting for AdGuard to restart"
  sleep 4
  for i in $(seq 1 20); do
    if curl -sf -u "$AGH_USER:$AGH_PASS" http://127.0.0.1:3000/control/status >/dev/null 2>&1; then
      printf "\n   $PASS AdGuard Home running\n\n"
      break
    fi
    if [ "$i" -eq 20 ]; then
      printf "\n   ${RED}AdGuard didn't restart cleanly. Check: journalctl -u AdGuardHome${NC}\n"
      exit 1
    fi
    printf "."
    sleep 1
  done

  # ── Set upstream DNS ────────────────────────────────────────────────────────
  echo "==> Setting upstream DNS (1.1.1.1, 9.9.9.9 — parallel)..."
  curl -s -X POST http://127.0.0.1:3000/control/dns_config \
    -u "$AGH_USER:$AGH_PASS" \
    -H "Content-Type: application/json" \
    -d '{"upstream_dns":["1.1.1.1","9.9.9.9"],"bootstrap_dns":["1.1.1.1:53"],"upstream_mode":"parallel"}' >/dev/null
  printf "   $PASS Upstream DNS configured\n\n"

  # ── Add blocklists ──────────────────────────────────────────────────────────
  echo "==> Adding blocklists..."
  for entry in \
    "AdGuard DNS filter|https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt" \
    "EasyList|https://easylist.to/easylist/easylist.txt" \
    "EasyPrivacy|https://easylist.to/easylist/easyprivacy.txt"; do
    LIST_NAME="${entry%%|*}"
    LIST_URL="${entry##*|}"
    curl -s -X POST http://127.0.0.1:3000/control/filtering/add_url \
      -u "$AGH_USER:$AGH_PASS" \
      -H "Content-Type: application/json" \
      -d "{\"name\":\"$LIST_NAME\",\"url\":\"$LIST_URL\",\"whitelist\":false}" >/dev/null
    printf "   $PASS $LIST_NAME\n"
  done

  # Trigger filter download
  curl -s -X POST "http://127.0.0.1:3000/control/filtering/refresh?force=true" \
    -u "$AGH_USER:$AGH_PASS" >/dev/null
  printf "\n"
fi

# ── Firewall: allow DNS only on wg0, not public internet ─────────────────────
echo "==> Configuring firewall (DNS on wg0 only)..."
ufw allow in on wg0 to any port 53 proto udp comment "AdGuard DNS (VPN only)"
ufw allow in on wg0 to any port 53 proto tcp comment "AdGuard DNS (VPN only)"
ufw allow in on wg0 to any port 3000 proto tcp comment "AdGuard UI (VPN only)"
printf "   $PASS Port 53/udp+tcp open on wg0 only\n"
printf "   $PASS Port 3000 open on wg0 only (default deny covers public internet)\n\n"

# ── Verify DNS is responding ──────────────────────────────────────────────────
echo "==> Verifying DNS on 10.0.0.1:53..."
sleep 2
if command -v dig &>/dev/null; then
  RESULT=$(dig @10.0.0.1 -p 53 google.com A +short +time=5 2>/dev/null || true)
  if [ -n "$RESULT" ]; then
    printf "   $PASS DNS resolving: google.com → ${CYAN}$RESULT${NC}\n\n"
  else
    printf "   ${YELLOW}DNS query returned no result — filters may still be loading. Try again in 30s.${NC}\n\n"
  fi
else
  printf "   ${YELLOW}dig not installed — skipping DNS check. Install dnsutils to test.${NC}\n\n"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
printf "${GREEN}${BOLD}"
cat << 'EOF'
  ╔══════════════════════════════════════════════╗
  ║      ADGUARD HOME LIVE. ADS BLOCKED.         ║
  ╚══════════════════════════════════════════════╝
EOF
printf "${NC}\n"

if [ "$FRESH_INSTALL" = true ]; then
  printf "  ${BOLD}Web UI credentials — save these:${NC}\n"
  printf "    Username: ${CYAN}$AGH_USER${NC}\n"
  printf "    Password: ${CYAN}$AGH_PASS${NC}\n\n"
  printf "  ${BOLD}Next step — on your Mac, run:${NC}\n\n"
  printf "  ${CYAN}bash adguard_client.sh${NC}\n\n"
fi
printf "  ${BOLD}Web UI (while connected to VPN):${NC}\n"
printf "  ${CYAN}http://10.0.0.1:3000${NC}\n\n"
printf "  ${BOLD}Verify blocking:${NC}\n"
printf "    ${CYAN}dig @10.0.0.1 doubleclick.net${NC}   # should return NXDOMAIN\n\n"
printf "${YELLOW}  Stay private. Block the noise. Question everything. Never trust your government. Stand against the machine.${NC}\n\n"
