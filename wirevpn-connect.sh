#!/bin/bash
# WireVPN boot connector — brings up tunnel, verifies DNS, stays resident for clean shutdown
# Installed to /usr/local/bin/wirevpn-connect.sh by client_setup.sh
# Run by LaunchDaemon com.wirevpn.startup at boot

LOG=/var/log/wirevpn.log
CONF=/etc/wireguard/client.conf

log() { echo "$(date): $1" >> "$LOG"; }

# ── Parse DNS servers from the client config — never hardcode ──
# Configs vary: 10.0.0.1 with AdGuard, 1.1.1.1 without. Reads the first
# uncommented "DNS =" line (comma-separated supported). Falls back to 10.0.0.1
# only when the config names no DNS server (legacy configs).
VPN_DNS_SERVERS=$(grep -E '^[[:space:]]*DNS[[:space:]]*=' "$CONF" 2>/dev/null | head -1 | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*#.*$//' | tr ',' ' ' | tr -s ' ')
VPN_DNS_SERVERS=${VPN_DNS_SERVERS:-10.0.0.1}
VPN_DNS=$(echo "$VPN_DNS_SERVERS" | awk '{print $1}')

# Persistent state for IPv6 leak protection (survives reboots)
V6_STATE="/etc/wireguard/.wirevpn_v6.state"

# ── Find wg-quick (PATH may be limited under launchd) ──
WG_QUICK=""
for p in /opt/homebrew/bin/wg-quick /usr/local/bin/wg-quick; do
    [ -x "$p" ] && { WG_QUICK="$p"; break; }
done
if [ -z "$WG_QUICK" ]; then
    log "FATAL: wg-quick not found"
    exit 1
fi

# ── Reset VPN DNS on all network interfaces ──
# wg-quick sets DNS on every interface, so cleanup must do the same
clear_vpn_dns_all() {
    local flushed=0
    while IFS= read -r svc; do
        [[ "$svc" == An* ]] && continue  # skip header line
        svc="${svc#\*}"                  # strip leading asterisk from disabled services
        svc="${svc# }"
        local dns server
        dns=$(networksetup -getdnsservers "$svc" 2>/dev/null | tr '\n' ' ')
        for server in $VPN_DNS_SERVERS; do
            if echo "$dns" | grep -qF "$server"; then
                networksetup -setdnsservers "$svc" empty 2>/dev/null
                log "Cleared stale VPN DNS ($server) on: $svc"
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
# the tunnel in cleartext. Disable v6 on all services before the tunnel comes
# up; restore on teardown. State file persists across reboots, and boot heals
# baseline first, so a crash or hard power loss can't leave v6 disabled.
disable_ipv6_all() {
    : > "$V6_STATE"
    local svc
    while IFS= read -r svc; do
        [[ "$svc" == An* ]] && continue  # skip header line
        svc="${svc#\*}"                  # strip leading asterisk from disabled services
        svc="${svc# }"
        [ -z "$svc" ] && continue
        if ! networksetup -getinfo "$svc" 2>/dev/null | grep -q "IPv6: Off"; then
            if networksetup -setv6off "$svc" 2>/dev/null; then
                echo "$svc" >> "$V6_STATE"
                log "IPv6 disabled on: $svc (leak protection)"
            fi
        fi
    done < <(networksetup -listallnetworkservices 2>/dev/null)
    [ -s "$V6_STATE" ] || rm -f "$V6_STATE"
}

restore_ipv6_all() {
    [ -f "$V6_STATE" ] || return 0
    local svc
    while IFS= read -r svc; do
        [ -z "$svc" ] && continue
        if networksetup -setv6automatic "$svc" 2>/dev/null; then
            log "IPv6 restored on: $svc"
        fi
    done < "$V6_STATE"
    rm -f "$V6_STATE"
}

# ── Phase 1: Clean stale VPN DNS from previous crash/hard reboot ──
clear_vpn_dns_all
# Heal any v6 state left by an unclean shutdown — always start from baseline
restore_ipv6_all

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
    # Belt-and-suspenders: wg-quick down restores DNS, but sweep all interfaces anyway
    clear_vpn_dns_all
    restore_ipv6_all
    exit 0
}
trap cleanup SIGTERM SIGINT

# ── Phase 3: Bring tunnel up ──
log "Network ready — starting WireGuard"
# Fail-closed: kill IPv6 before the tunnel exists so nothing leaks in the gap
disable_ipv6_all
if ! $WG_QUICK up "$CONF" >> "$LOG" 2>&1; then
    log "wg-quick up failed — sweeping DNS on all interfaces"
    clear_vpn_dns_all
    restore_ipv6_all
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
    log "Tearing down tunnel and sweeping DNS on all interfaces"
    $WG_QUICK down "$CONF" >> "$LOG" 2>&1
    clear_vpn_dns_all
    restore_ipv6_all
    log "DNS restored to DHCP — network functional without VPN"
    exit 1
fi

log "Tunnel UP — DNS verified through ${VPN_DNS} — VPN operational"

# ── Phase 5: Stay resident to catch shutdown signals ──
# launchd sends SIGTERM during system shutdown; our trap handles clean teardown
while true; do sleep 86400; done
