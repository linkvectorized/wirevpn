# WireVPN

```
  ██╗    ██╗██╗██████╗ ███████╗██╗   ██╗██████╗ ███╗   ██╗
  ██║    ██║██║██╔══██╗██╔════╝██║   ██║██╔══██╗████╗  ██║
  ██║ █╗ ██║██║██████╔╝█████╗  ██║   ██║██████╔╝██╔██╗ ██║
  ██║███╗██║██║██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║
  ╚███╔███╔╝██║██║  ██║███████╗ ╚████╔╝ ██║     ██║ ╚████║
   ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚═╝     ╚═╝  ╚═══╝
```

> ⚠️ Your traffic belongs to you. Not your ISP. Not your government. Not big tech.
> Route around surveillance. Stay sovereign. Question everything.

Self-hosted WireGuard VPN — spin up your own private tunnel on any VPS in minutes. No subscriptions. No third party logging your data. No trust required.

![WireVPN Tunnel Diagram](tunnel.svg)

```
You → encrypted tunnel → YOUR server → internet
ISP sees: encrypted gibberish to one IP
World sees: your VPS, not you
```

---

## What's in here

```
server_setup.sh   — run on your VPS (Ubuntu 24.04)
client_setup.sh   — run on your Mac or Linux machine
```

### Persistence — how it works

The `client_setup.sh` script automatically installs a boot daemon so your VPN reconnects every time your machine starts — no manual intervention needed.

**macOS** — installs a launchd daemon (`/Library/LaunchDaemons/com.wirevpn.startup.plist`) with a network-wait wrapper that holds off until your internet is up before connecting.

**Linux** — enables a systemd service (`wg-quick@client`) with `network-online.target` so WireGuard waits for network before starting.

Without this, your VPN dies on restart and you're exposed until you manually reconnect.

---

## What you need

- A VPS running Ubuntu 24.04 (Vultr, Hetzner, DigitalOcean — ~$5/month)
- A Mac or Linux machine as your client
- 20 minutes

## Client OS support

```
macOS    ✓   auto-start via launchd
Linux    ✓   auto-start via systemd (apt / dnf / pacman)
Windows  ✗   not supported
```

---

## Setup

### 1. Spin up a VPS
Get a cheap Ubuntu 24.04 VPS anywhere. Vultr VC2-1C-1GB or similar is plenty.
Pay with crypto if you want to keep it clean.

### 2. Run the server script on your VPS
```bash
ssh root@YOUR_SERVER_IP
bash <(curl -fsSL https://raw.githubusercontent.com/linkvectorized/wirevpn/main/server_setup.sh)
```

It will:
- Install WireGuard
- Generate server + client keys
- Configure routing and firewall
- Write your client config to `/etc/wireguard/client.conf`

### 3. Pull the client config to your Mac
```bash
mkdir -p ~/WireVPN
scp root@YOUR_SERVER_IP:/etc/wireguard/client.conf ~/WireVPN/client.conf
```

### 4. Run the client script on your Mac
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/linkvectorized/wirevpn/main/client_setup.sh)
```

It will:
- Install WireGuard tools via Homebrew
- Fix config permissions
- Install a launchd daemon so VPN auto-connects on boot
- Connect the tunnel
- Verify your exit IP

### 5. Verify
```bash
curl ifconfig.me
# should return your VPS IP, not your home IP
```

---

## Useful commands

```bash
# Connect
sudo wg-quick up /etc/wireguard/client.conf

# Disconnect
sudo wg-quick down /etc/wireguard/client.conf

# Check status
sudo wg show

# Check your exit IP
curl ifconfig.me

# View logs (macOS)
cat /var/log/wirevpn.log

# View logs (Linux)
sudo journalctl -u wg-quick@client
```

## Internet not working?

If you destroyed your VPS while the VPN was still connected, all traffic is tunneling into nothing. Run:

```bash
# Try this first
sudo wg-quick down /etc/wireguard/client.conf

# If that doesn't work, kill the process directly
sudo killall wireguard-go
```

Your internet will come back immediately. Reconnect once your new VPS is ready.

---

## Harden SSH access (recommended)

By default your VPS uses password auth. Switch to SSH keys — much harder to brute force.

**1. Generate a key on your local machine (if you don't have one):**
```bash
ssh-keygen -t ed25519 -C "your-label"
```
Use a passphrase when prompted — if your key file is ever stolen, the attacker still can't use it.

**2. Copy your public key to the server:**
```bash
ssh-copy-id root@YOUR_SERVER_IP
```

**3. Test that key auth works:**
```bash
ssh root@YOUR_SERVER_IP
# should log in without asking for password
```

**4. Disable password auth entirely:**
```bash
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd
```

After this, no one gets in without your private key — even if they know the root password.

---

## "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED"

If your VPS provider reused the same IP for your new server you'll get this SSH error. Safe to fix — just remove the old key:

```bash
ssh-keygen -R YOUR_SERVER_IP
```

Then SSH in again normally.

---

## Why self-host?

Commercial VPNs ask you to trust them. Why would you?

```
Commercial VPN:   You → their server → internet
                  They log everything. They comply with subpoenas.
                  You're paying someone else to surveil you.

Self-hosted:      You → your server → internet
                  You own the keys. You own the logs (there are none).
                  Zero trust required.
```

---

## Limitations

- Single client per server (add more `[Peer]` blocks to `/etc/wireguard/wg0.conf` manually for more devices)
- IPv4 only — no IPv6 support
- macOS and Linux client only — no Windows support

---

## Threat model

This protects you from:
- ✓ ISP seeing your browsing traffic
- ✓ Network-level surveillance on public WiFi
- ✓ Ad networks correlating your IP
- ✓ Basic geo-restrictions

This does NOT protect you from:
- ✗ Your VPS provider (pick one you trust, pay anonymously if needed)
- ✗ Browser fingerprinting
- ✗ Being logged in to accounts that identify you
- ✗ Nation-state level adversaries

---

*Stay private. Question narratives. Build cool things.*

— [linkvectorized](https://github.com/linkvectorized)
