#!/bin/bash
# wirevpn — manage your WireGuard VPN tunnel
# Installed to /usr/local/bin/wirevpn by client_setup.sh
# Usage: sudo wirevpn [up|down|status]

CONF="/etc/wireguard/client.conf"
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

# ── Parse DNS servers from the client config — never hardcode ──
# Configs vary: 10.0.0.1 with AdGuard, 1.1.1.1 without. Reads the first
# uncommented "DNS =" line (comma-separated supported). Falls back to 10.0.0.1
# only when the config names no DNS server (legacy configs).
VPN_DNS_SERVERS=$(grep -E '^[[:space:]]*DNS[[:space:]]*=' "$CONF" 2>/dev/null | head -1 | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*#.*$//' | tr ',' ' ' | tr -s ' ')
VPN_DNS_SERVERS=${VPN_DNS_SERVERS:-10.0.0.1}
VPN_DNS=$(echo "$VPN_DNS_SERVERS" | awk '{print $1}')

# ── DNS sweep (macOS only) ─────────────────────────────────────────────────────
clear_vpn_dns_all() {
    local flushed=0
    while IFS= read -r svc; do
        [[ "$svc" == An* ]] && continue
        svc="${svc#\*}"
        svc="${svc# }"
        local dns server
        dns=$(networksetup -getdnsservers "$svc" 2>/dev/null | tr '\n' ' ')
        for server in $VPN_DNS_SERVERS; do
            if echo "$dns" | grep -qF "$server"; then
                networksetup -setdnsservers "$svc" empty 2>/dev/null
                printf "   $PASS DNS cleared (%s) on: %s\n" "$server" "$svc"
                flushed=1
                break
            fi
        done
    done < <(networksetup -listallnetworkservices 2>/dev/null)
    if [ "$flushed" -eq 1 ]; then
        dscacheutil -flushcache 2>/dev/null
        killall -HUP mDNSResponder 2>/dev/null
    fi
}

# ── IPv6 leak protection (fail-closed) ──
# AllowedIPs = 0.0.0.0/0 covers IPv4 only — without this, IPv6 traffic bypasses
# the tunnel in cleartext. Disable v6 while the tunnel is up; restore on
# teardown. macOS state persists across reboots (/etc/wireguard); Linux state
# lives in /run and auto-heals on reboot (sysctl default is v6 enabled).
if [ "$PLATFORM" = "macos" ]; then
    V6_STATE="/etc/wireguard/.wirevpn_v6.state"
else
    V6_STATE="/run/wirevpn_v6.state"
fi

disable_ipv6_all() {
    if [ "$PLATFORM" = "macos" ]; then
        : > "$V6_STATE"
        local svc
        while IFS= read -r svc; do
            [[ "$svc" == An* ]] && continue
            svc="${svc#\*}"
            svc="${svc# }"
            [ -z "$svc" ] && continue
            if ! networksetup -getinfo "$svc" 2>/dev/null | grep -q "IPv6: Off"; then
                if networksetup -setv6off "$svc" 2>/dev/null; then
                    echo "$svc" >> "$V6_STATE"
                    printf "   $PASS IPv6 disabled on: %s (leak protection)\n" "$svc"
                fi
            fi
        done < <(networksetup -listallnetworkservices 2>/dev/null)
        [ -s "$V6_STATE" ] || rm -f "$V6_STATE"
    else
        cat /proc/sys/net/ipv6/conf/all/disable_ipv6 > "$V6_STATE" 2>/dev/null || true
        sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
        sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
        printf "   $PASS IPv6 disabled (leak protection)\n"
    fi
}

restore_ipv6_all() {
    if [ "$PLATFORM" = "macos" ]; then
        [ -f "$V6_STATE" ] || return 0
        local svc
        while IFS= read -r svc; do
            [ -z "$svc" ] && continue
            if networksetup -setv6automatic "$svc" 2>/dev/null; then
                printf "   $PASS IPv6 restored on: %s\n" "$svc"
            fi
        done < "$V6_STATE"
        rm -f "$V6_STATE"
    else
        [ -f "$V6_STATE" ] || return 0
        local prev
        prev=$(cat "$V6_STATE" 2>/dev/null || echo 0)
        sysctl -w "net.ipv6.conf.all.disable_ipv6=${prev:-0}" >/dev/null 2>&1
        sysctl -w "net.ipv6.conf.default.disable_ipv6=${prev:-0}" >/dev/null 2>&1
        rm -f "$V6_STATE"
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
        # Fail-closed: kill IPv6 before the tunnel exists so nothing leaks in the gap
        disable_ipv6_all
        if ! sudo "$WG_QUICK" up "$CONF" 2>&1; then
            printf "$FAIL Failed to bring tunnel up.\n"
            restore_ipv6_all
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
            restore_ipv6_all
            exit 1
        fi
    else
        disable_ipv6_all
        if ! sudo systemctl start wg-quick@client; then
            printf "$FAIL Failed to start WireGuard.\n"
            restore_ipv6_all
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

        # Restore IPv6 disabled by leak protection
        restore_ipv6_all
    else
        if ! sudo systemctl stop wg-quick@client; then
            printf "$FAIL Failed to stop WireGuard.\n"
            exit 1
        fi
        restore_ipv6_all
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
