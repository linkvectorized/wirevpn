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
# Stop existing service gracefully before overwriting
if systemctl is-active --quiet AdGuardHome 2>/dev/null; then
  systemctl stop AdGuardHome
fi
mkdir -p "$AGH_DIR"
tar -xzf "$TMP_DIR/agh.tar.gz" -C "$TMP_DIR"
cp "$TMP_DIR/AdGuardHome/AdGuardHome" "$AGH_BIN"
chmod 755 "$AGH_BIN"
rm -rf "$TMP_DIR"
printf "   $PASS Binary installed at $AGH_BIN\n\n"

# ── Write config ──────────────────────────────────────────────────────────────
echo "==> Writing AdGuardHome.yaml..."
# Back up existing config if present
if [ -f "$AGH_CONF" ]; then
  cp "$AGH_CONF" "${AGH_CONF}.bak"
  printf "   ${YELLOW}Existing config backed up to AdGuardHome.yaml.bak${NC}\n"
fi

cat > "$AGH_CONF" << 'YAMLEOF'
http:
  address: 0.0.0.0:3000

dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  upstream_dns:
    - 1.1.1.1
    - 9.9.9.9
  bootstrap_dns:
    - 1.1.1.1
  cache_size: 4194304
  cache_ttl_min: 0
  cache_ttl_max: 0

filtering:
  enabled: true
  filters:
    - enabled: true
      url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
      name: AdGuard DNS filter
      id: 1
    - enabled: true
      url: https://easylist.to/easylist/easylist.txt
      name: EasyList
      id: 2
    - enabled: true
      url: https://easylist.to/easylist/easyprivacy.txt
      name: EasyPrivacy
      id: 3

querylog:
  enabled: false

statistics:
  enabled: false

log:
  enabled: false
YAMLEOF

chmod 600 "$AGH_CONF"
printf "   $PASS Config written\n\n"

# ── Register systemd service ──────────────────────────────────────────────────
echo "==> Registering AdGuardHome as a systemd service..."
if ! systemctl is-enabled AdGuardHome &>/dev/null 2>&1; then
  "$AGH_BIN" -s install
fi
printf "   $PASS Service registered\n\n"

# ── Start AdGuard Home ────────────────────────────────────────────────────────
echo "==> Starting AdGuard Home..."
systemctl enable AdGuardHome -q
if ! systemctl restart AdGuardHome; then
  printf "${RED}AdGuardHome failed to start. Check: systemctl status AdGuardHome${NC}\n"
  exit 1
fi
sleep 2
if ! systemctl is-active --quiet AdGuardHome; then
  printf "${RED}AdGuardHome started but is not active. Check: journalctl -u AdGuardHome${NC}\n"
  exit 1
fi
printf "   $PASS AdGuard Home running\n\n"

# ── Firewall: allow DNS only on wg0, not public internet ─────────────────────
echo "==> Configuring firewall (DNS on wg0 only)..."
# Allow DNS from VPN clients only — never expose port 53 publicly
ufw allow in on wg0 to any port 53 proto udp comment "AdGuard DNS (VPN only)"
ufw allow in on wg0 to any port 53 proto tcp comment "AdGuard DNS (VPN only)"
# Web UI — only reachable through the tunnel, not from public internet
ufw deny 3000/tcp comment "AdGuard UI — not public" 2>/dev/null || true
printf "   $PASS Port 53/udp+tcp open on wg0 only\n"
printf "   $PASS Port 3000 blocked from public internet\n\n"

# ── Verify DNS is responding ──────────────────────────────────────────────────
echo "==> Verifying DNS on 10.0.0.1:53..."
sleep 1
if command -v dig &>/dev/null; then
  RESULT=$(dig @10.0.0.1 -p 53 google.com A +short +time=3 2>/dev/null || true)
  if [ -n "$RESULT" ]; then
    printf "   $PASS DNS resolving: google.com → ${CYAN}$RESULT${NC}\n\n"
  else
    printf "   ${YELLOW}DNS query returned no result — AdGuard may still be loading filters. Try again in 30s.${NC}\n\n"
  fi
else
  printf "   ${YELLOW}dig not installed — skipping DNS verification. Install dnsutils to test.${NC}\n\n"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
printf "${GREEN}${BOLD}"
cat << 'EOF'
  ╔══════════════════════════════════════════════╗
  ║      ADGUARD HOME LIVE. ADS BLOCKED.         ║
  ╚══════════════════════════════════════════════╝
EOF
printf "${NC}\n"

printf "  ${BOLD}Next step — on your Mac, run:${NC}\n\n"
printf "  ${CYAN}bash adguard_client.sh${NC}\n\n"
printf "  ${BOLD}Web UI (while connected to VPN):${NC}\n"
printf "  ${CYAN}http://10.0.0.1:3000${NC}\n\n"
printf "  ${BOLD}Verify it's working:${NC}\n"
printf "    ${CYAN}dig @10.0.0.1 doubleclick.net${NC}   # should return NXDOMAIN\n\n"
printf "${YELLOW}  Stay private. Block the noise. Question everything.${NC}\n\n"
