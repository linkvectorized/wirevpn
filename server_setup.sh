#!/usr/bin/env bash
# server_setup.sh — WireGuard VPN server setup
# Run this on your fresh Ubuntu 24.04 VPS as root

set -e

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

PASS="${GREEN}[✓]${NC}"
FAIL="${RED}[✗]${NC}"

# ── Intro ─────────────────────────────────────────────────────────────────────
clear
printf "${CYAN}"
cat << 'EOF'
  ╔══════════════════════════════════════════════╗
  ║         WireVPN — Server Setup               ║
  ╚══════════════════════════════════════════════╝
EOF
printf "${NC}\n"
printf "${YELLOW}  ⚠  Your data belongs to you. Not your ISP. Not big tech.${NC}\n\n"
sleep 1

# ── Check root ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  printf "${RED}Run this as root.${NC}\n"
  exit 1
fi

# ── Detect public IP ──────────────────────────────────────────────────────────
printf "${BOLD}==> Detecting public IP...${NC}\n"
SERVER_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || true)
if [ -z "$SERVER_IP" ] || ! echo "$SERVER_IP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
  printf "${RED}Failed to detect public IP. Check your network and try again.${NC}\n"
  exit 1
fi
printf "   $PASS Server IP: ${CYAN}$SERVER_IP${NC}\n\n"

# ── Update system ─────────────────────────────────────────────────────────────
printf "${BOLD}==> Updating system...${NC}\n"
apt-get update -qq && apt-get upgrade -y -qq
printf "   $PASS System updated\n\n"

# ── Install WireGuard ─────────────────────────────────────────────────────────
printf "${BOLD}==> Installing WireGuard...${NC}\n"
apt-get install -y -qq wireguard ufw
printf "   $PASS WireGuard installed\n\n"

# ── Generate server keys ──────────────────────────────────────────────────────
printf "${BOLD}==> Generating server keys...${NC}\n"
mkdir -p /etc/wireguard
# Back up existing config if present
if [ -f /etc/wireguard/wg0.conf ]; then
  cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.bak
  printf "   ${YELLOW}Existing wg0.conf backed up to wg0.conf.bak${NC}\n"
fi
wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
chmod 600 /etc/wireguard/server_private.key
SERVER_PRIVATE=$(cat /etc/wireguard/server_private.key)
SERVER_PUBLIC=$(cat /etc/wireguard/server_public.key)
printf "   $PASS Server keys generated\n\n"

# ── Generate client keys ──────────────────────────────────────────────────────
printf "${BOLD}==> Generating client keys...${NC}\n"
wg genkey | tee /etc/wireguard/client_private.key | wg pubkey > /etc/wireguard/client_public.key
chmod 600 /etc/wireguard/client_private.key
CLIENT_PRIVATE=$(cat /etc/wireguard/client_private.key)
CLIENT_PUBLIC=$(cat /etc/wireguard/client_public.key)
printf "   $PASS Client keys generated\n\n"

# ── Detect network interface ──────────────────────────────────────────────────
printf "${BOLD}==> Detecting network interface...${NC}\n"
NET_IF=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$NET_IF" ]; then
  printf "${RED}Could not detect network interface. No default route found.${NC}\n"
  exit 1
fi
printf "   $PASS Interface: ${CYAN}$NET_IF${NC}\n\n"

# ── Write server config ───────────────────────────────────────────────────────
printf "${BOLD}==> Writing server config...${NC}\n"
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE

# NAT — routes client traffic out through $NET_IF
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $NET_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $NET_IF -j MASQUERADE

[Peer]
# Client — add more [Peer] blocks for additional devices
PublicKey = $CLIENT_PUBLIC
AllowedIPs = 10.0.0.2/32
EOF
chmod 600 /etc/wireguard/wg0.conf
printf "   $PASS Server config written\n\n"

# ── Enable IP forwarding ──────────────────────────────────────────────────────
printf "${BOLD}==> Enabling IP forwarding...${NC}\n"
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -p -q
printf "   $PASS IP forwarding enabled\n\n"

# ── Start WireGuard ───────────────────────────────────────────────────────────
printf "${BOLD}==> Starting WireGuard...${NC}\n"
systemctl enable wg-quick@wg0 -q
if ! systemctl start wg-quick@wg0; then
  printf "${RED}WireGuard failed to start. Check: systemctl status wg-quick@wg0${NC}\n"
  exit 1
fi
if ! systemctl is-active --quiet wg-quick@wg0; then
  printf "${RED}WireGuard started but is not active. Check: systemctl status wg-quick@wg0${NC}\n"
  exit 1
fi
printf "   $PASS WireGuard running\n\n"

# ── Open firewall port ────────────────────────────────────────────────────────
printf "${BOLD}==> Configuring firewall...${NC}\n"
ufw allow 51820/udp
ufw allow ssh
ufw --force enable
printf "   $PASS Port 51820/udp open\n\n"

# ── Write client config ───────────────────────────────────────────────────────
printf "${BOLD}==> Writing client config...${NC}\n"
cat > /etc/wireguard/client.conf <<CLIENTCONF
[Interface]
PrivateKey = $CLIENT_PRIVATE
Address = 10.0.0.2/24
# DNS = 1.1.1.1 (Cloudflare) — change to 9.9.9.9 (Quad9) or your preferred DNS
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC
Endpoint = $SERVER_IP:51820
AllowedIPs = 0.0.0.0/0
# PersistentKeepalive keeps tunnel alive through NAT (25s is standard)
PersistentKeepalive = 25
CLIENTCONF
chmod 600 /etc/wireguard/client.conf
printf "   $PASS Client config written\n\n"

# ── Done ──────────────────────────────────────────────────────────────────────
printf "${GREEN}${BOLD}"
cat << 'EOF'
  ╔══════════════════════════════════════════════╗
  ║         SERVER READY. TUNNEL IS LIVE.        ║
  ╚══════════════════════════════════════════════╝
EOF
printf "${NC}\n"

printf "  ${BOLD}Next step — on your local machine run:${NC}\n\n"
printf "  ${CYAN}mkdir -p ~/WireVPN${NC}\n"
printf "  ${CYAN}scp root@$SERVER_IP:/etc/wireguard/client.conf ~/WireVPN/client.conf${NC}\n"
printf "  ${CYAN}bash <(curl -fsSL https://raw.githubusercontent.com/linkvectorized/wirevpn/main/client_setup.sh)${NC}\n\n"
printf "${YELLOW}  Stay private. Question everything.${NC}\n\n"
