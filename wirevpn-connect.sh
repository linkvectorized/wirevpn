#!/bin/bash
# WireVPN boot connector — brings up tunnel, verifies DNS, stays resident for clean shutdown
# Installed to /usr/local/bin/wirevpn-connect.sh by client_setup.sh
# Run by LaunchDaemon com.wirevpn.startup at boot

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
    # Belt-and-suspenders: verify DNS was restored
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
