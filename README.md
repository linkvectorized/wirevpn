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
server_setup.sh     — run on your VPS (Ubuntu 24.04)
client_setup.sh     — run on your Mac or Linux machine
add_peer.sh         — add or remove devices from your VPN (run on your Mac)
adguard_setup.sh    — install AdGuard Home on your VPS for DNS-level ad blocking
adguard_client.sh   — update Mac configs to use AdGuard DNS
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

## Adding and removing devices

Each device needs its own **peer** — unique keys and IP so multiple devices can connect simultaneously.

```bash
# Add a new device (generates a QR code to scan)
bash add_peer.sh phone
bash add_peer.sh laptop
bash add_peer.sh brian

# Remove a device (revokes access immediately, no restart needed)
bash add_peer.sh remove phone
```

Run this on your Mac. It will:
- Auto-detect your VPS IP from `client.conf`
- Generate a unique keypair and tunnel IP for the device
- Add the peer to your live WireGuard server (no restart)
- Pull the config to `~/Desktop/WireVPN/<name>.conf`
- Print a QR code — scan with the WireGuard iOS/Android app

Each device gets its own IP in the `10.0.0.x` range:
```
Mac Mini  → 10.0.0.2
iPhone    → 10.0.0.3
Laptop    → 10.0.0.4
...
```

Removing a peer revokes access instantly — they're kicked off the live tunnel and their keys are deleted from the server.

---

## AdGuard Home — DNS-level ad and tracker blocking

Block ads, trackers, and malware domains before they load — for every device already on your tunnel. No per-device changes needed.

AdGuard Home runs on your VPS and intercepts all DNS queries at `10.0.0.1`. When your iPhone or Mac asks "what's the IP for doubleclick.net?" AdGuard answers NXDOMAIN before the request ever leaves your network.

```
server_setup.sh     — install WireGuard
adguard_setup.sh    — install AdGuard Home (run after server_setup.sh)
adguard_client.sh   — update Mac configs to use AdGuard DNS
```

### 1. Run on your VPS (after server_setup.sh)
```bash
ssh root@YOUR_SERVER_IP
bash <(curl -fsSL https://raw.githubusercontent.com/linkvectorized/wirevpn/main/adguard_setup.sh)
```

It will:
- Download and install AdGuard Home binary
- Write a config with ad/tracker/malware blocklists
- Lock DNS to the WireGuard interface only — port 53 is never exposed publicly
- Start AdGuard as a systemd service

### 2. Run on your Mac
```bash
cd ~/Desktop/WireVPN
bash adguard_client.sh
```

It will:
- Update DNS in all your `.conf` files (client.conf, phone.conf, etc.) from `1.1.1.1` to `10.0.0.1`
- Back up originals before editing
- Reinstall configs to `/etc/wireguard/`
- Bounce the tunnel to pick up the new DNS
- Verify blocking is working

### 3. For other devices (iPhone, etc.)
Edit the WireGuard config on each device and change:
```
DNS = 1.1.1.1
```
to:
```
DNS = 10.0.0.1
```

Or use `bash add_peer.sh <name>` — after running `adguard_client.sh`, new peer configs will automatically use AdGuard DNS.

### Web UI
While connected to your VPN, open:
```
http://10.0.0.1:3000
```

The UI is only reachable through the tunnel — it's not exposed to the public internet.

### Verify it's working

**1. Check a known ad domain is blocked**
```bash
dig @10.0.0.1 doubleclick.net
```
Should return `0.0.0.0` in the answer section. That means AdGuard intercepted the DNS query and returned a null address instead of the real one — the ad server is unreachable before any connection is even attempted.

How `dig` works here:
- `dig` is a DNS lookup tool — it asks a DNS server "what's the IP for this domain?"
- `@10.0.0.1` tells it to ask *your* AdGuard instance specifically, not your system DNS
- A normal domain returns a real IP like `142.250.80.1`
- A blocked domain returns `0.0.0.0` (null) or NXDOMAIN — AdGuard is lying to the requester on purpose, making the domain effectively unreachable

**2. Confirm you're still routing through your VPS**
```bash
curl ifconfig.me
```
Should return `137.220.56.59` — your VPS IP, not your home IP.

**3. Open the web UI**
```bash
open http://10.0.0.1:3000
```
Shows live query stats, blocked domains, and filter list management. Only reachable while connected to your VPN.

### Blocklists included by default
- **AdGuard DNS filter** — ads, trackers, malware
- **EasyList** — display ads
- **EasyPrivacy** — tracking scripts

You can add more via the web UI under Filters → DNS blocklists.

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

## Mobile setup (iOS / Android)

1. Install the **WireGuard** app (free, by WireGuard Development Team)
2. On your Mac run: `bash add_peer.sh phone` — it prints a QR code
3. In the app tap `+` → **Create from QR code** → scan → done

**Enable On-Demand (auto-connect without toggling manually):**

In the WireGuard iOS app:
- Open the tunnel → tap **Edit**
- Toggle on **On-Demand Activation**
- Choose: WiFi, cellular, or both

With On-Demand enabled your phone connects automatically whenever it's on the networks you selected — no manual toggle needed.

---

## Limitations

- IPv4 only — no IPv6 support
- macOS and Linux client only — no Windows support
- Multiple devices: use `bash add_peer.sh <name>` — each gets its own keys and IP

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

## License

MIT — free for everyone, forever. Use it, fork it, modify it, share it.

---

*Stay private. Question narratives. Build cool things.*

— [linkvectorized](https://github.com/linkvectorized)
