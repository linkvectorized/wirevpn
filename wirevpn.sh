#!/bin/bash
# wirevpn — manage your WireGuard VPN tunnel
# Installed to /usr/local/bin/wirevpn by client_setup.sh
# Usage: sudo wirevpn [up|down|status]

CONF="/etc/wireguard/client.conf"
VPN_DNS="10.0.0.1"
PLIST="/Library/LaunchDaemons/com.wirevpn.startup.plist"

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

PASS="${GREEN}[✓]${NC}"
FAIL="${RED}[✗]${NC}"

# ── Detect OS ──────────────────────────────────────────────────────────────────
OS=$(uname -s)
[ "$OS" = "Darwin" ] && PLATFORM="macos" || PLATFORM="linux"

# ── Find wg-quick ──────────────────────────────────────────────────────────────
WG_QUICK=""
for p in /opt/homebrew/bin/wg-quick /usr/local/bin/wg-quick; do
    [ -x "$p" ] && { WG_QUICK="$p"; break; }
done
[ -z "$WG_QUICK" ] && WG_QUICK="$(command -v wg-quick 2>/dev/null || true)"

# ── DNS sweep (macOS only) ─────────────────────────────────────────────────────
clear_vpn_dns_all() {
    local flushed=0
    while IFS= read -r svc; do
        [[ "$svc" == An* ]] && continue
        svc="${svc#\*}"
        svc="${svc# }"
        local dns
        dns=$(networksetup -getdnsservers "$svc" 2>/dev/null | tr '\n' ' ')
        if echo "$dns" | grep -qF "$VPN_DNS"; then
            networksetup -setdnsservers "$svc" empty 2>/dev/null
            printf "   $PASS DNS cleared on: %s\n" "$svc"
            flushed=1
        fi
    done < <(networksetup -listallnetworkservices 2>/dev/null)
    if [ "$flushed" -eq 1 ]; then
        dscacheutil -flushcache 2>/dev/null
        killall -HUP mDNSResponder 2>/dev/null
    fi
}

# ── tunnel_up ──────────────────────────────────────────────────────────────────
cmd_up() {
    if sudo wg show 2>/dev/null | grep -q "interface"; then
        printf "${YELLOW}Tunnel is already up. Run 'sudo wirevpn status' to check.${NC}\n"
        exit 0
    fi

    if [ -z "$WG_QUICK" ]; then
        printf "${RED}wg-quick not found. Is WireGuard installed?${NC}\n"
        exit 1
    fi

    printf "${BOLD}Bringing tunnel up...${NC}\n"

    if [ "$PLATFORM" = "macos" ]; then
        if ! sudo "$WG_QUICK" up "$CONF" 2>&1; then
            printf "$FAIL Failed to bring tunnel up.\n"
            exit 1
        fi

        printf "${BOLD}Verifying DNS...${NC}\n"
        DNS_OK=false
        for attempt in 1 2 3; do
            if /usr/bin/dig +short +time=3 +tries=1 "@${VPN_DNS}" google.com 2>/dev/null | grep -qE '^[0-9]+\.'; then
                DNS_OK=true
                break
            fi
            sleep 2
        done

        if [ "$DNS_OK" = false ]; then
            printf "$FAIL DNS verification failed — tearing back down.\n"
            sudo "$WG_QUICK" down "$CONF" 2>/dev/null
            clear_vpn_dns_all
            exit 1
        fi
    else
        if ! sudo systemctl start wg-quick@client; then
            printf "$FAIL Failed to start WireGuard.\n"
            exit 1
        fi
        sleep 2
    fi

    MY_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || echo "unknown")
    printf "$PASS Tunnel UP — exit IP: ${CYAN}%s${NC}\n" "$MY_IP"
}

# ── tunnel_down ────────────────────────────────────────────────────────────────
cmd_down() {
    if [ "$PLATFORM" = "macos" ]; then
        # If the LaunchDaemon is loaded, unload it — sends SIGTERM to wirevpn-connect.sh
        # which fires its cleanup trap: wg-quick down + clear_vpn_dns_all
        if sudo launchctl list 2>/dev/null | grep -q "com.wirevpn.startup"; then
            printf "${BOLD}Stopping daemon...${NC}\n"
            sudo launchctl unload "$PLIST" 2>/dev/null
            sleep 2  # give the trap time to run
        fi

        # Belt and suspenders: if tunnel is still up, bring it down
        if [ -n "$WG_QUICK" ] && sudo wg show 2>/dev/null | grep -q "interface"; then
            sudo "$WG_QUICK" down "$CONF" 2>/dev/null
        fi

        # Always sweep DNS — don't trust wg-quick to have done it cleanly
        clear_vpn_dns_all
    else
        if ! sudo systemctl stop wg-quick@client; then
            printf "$FAIL Failed to stop WireGuard.\n"
            exit 1
        fi
    fi

    printf "$PASS Tunnel down. DNS restored.\n"
}

# ── status ─────────────────────────────────────────────────────────────────────
cmd_status() {
    printf "\n${BOLD}── Tunnel ──${NC}\n"
    if sudo wg show 2>/dev/null | grep -q "interface"; then
        printf "$PASS Status: ${GREEN}UP${NC}\n\n"
        sudo wg show
    else
        printf "$FAIL Status: ${RED}DOWN${NC}\n"
    fi

    printf "\n${BOLD}── Exit IP ──${NC}\n"
    MY_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || echo "unavailable")
    printf "   %s\n" "$MY_IP"

    if [ "$PLATFORM" = "macos" ]; then
        printf "\n${BOLD}── DNS ──${NC}\n"
        while IFS= read -r svc; do
            [[ "$svc" == An* ]] && continue
            svc="${svc#\*}"
            svc="${svc# }"
            dns=$(networksetup -getdnsservers "$svc" 2>/dev/null)
            [[ "$dns" == *"There aren't"* ]] && continue
            printf "   %-20s %s\n" "$svc" "$(echo "$dns" | tr '\n' ' ')"
        done < <(networksetup -listallnetworkservices 2>/dev/null)
    fi
    printf "\n"
}

# ── dispatch ───────────────────────────────────────────────────────────────────
case "${1:-}" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    *)
        printf "Usage: sudo wirevpn [up|down|status]\n"
        printf "\n"
        printf "  up      Bring the tunnel up and verify DNS\n"
        printf "  down    Tear the tunnel down cleanly and restore DNS\n"
        printf "  status  Show tunnel state, exit IP, and DNS servers\n\n"
        exit 1
        ;;
esac
