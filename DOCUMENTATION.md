# TCP Tunnel Project - Full Documentation

## Project Goal

Create a tunnel between two Linux servers:
- **Iran server** (`vm-223662`, IP: `5.122.242.137`) — acts as a **relay**
- **Kharej server** (`vmfatemehrsthxxxffwkhmmtdq`, IP: `54.38.137.45`) — acts as **gateway** (OVH datacenter)

**Use case**: V2Ray users connect to Iran server on any port → traffic is relayed to Kharej server → exits to internet via Kharej.

```
V2Ray User ──► Iran:ANY_PORT ──[tunnel]──► Kharej (x-ui/Xray) ──► Internet
```

---

## Server Details

### Iran Server (Relay/Client)
- **Hostname**: `vm-223662`
- **Public IP**: `5.122.242.137`
- **NAT IP (as seen externally)**: `87.248.155.45`
- **OS**: Ubuntu 22.04 (OpenSSH_8.9p1, OpenSSL 3.0.2)
- **SSH port**: `9011` (non-standard)
- **Role**: Relay — forward all incoming ports to Kharej

### Kharej Server (Gateway)
- **Hostname**: `vmfatemehrsthxxxffwkhmmtdq`
- **Public IP**: `54.38.137.45`
- **OS**: Ubuntu 22.04 (OpenSSH_8.9p1 Ubuntu-3ubuntu0.13)
- **SSH port**: `22`
- **x-ui**: Installed at `/usr/local/x-ui/` (Xray management panel)
- **Role**: Gateway — runs V2Ray/Xray, traffic exits to internet

---

## What Was Tried & Results

### 1. GRE Tunnel (FAILED)
- **Method**: `ip tunnel add mode gre` (IP Protocol 47)
- **Result**: Blocked. ISP filters all non-TCP/UDP protocols.
- **Reason**: GRE uses IP Protocol 47, not TCP/UDP. Iran ISP blocks it at backbone level. Also unencrypted, easily detected by DPI.

### 2. Direct SSH on Port 443 (FAILED)
- **Method**: SSH TUN tunnel (`ssh -w 0:0`) on port 443
- **Result**: Blocked. ISP transparent proxy intercepts port 443.
- **Evidence**: Kharej auth.log shows `GET / HTTP/1.1` from Iran's IP instead of SSH protocol. ISP sends HTTP probes to detect the service.
- **Log**:
  ```
  sshd[17641]: error: kex_exchange_identification: client sent invalid protocol identifier "GET / HTTP/1.1"
  banner exchange: Connection from 5.122.242.137 port 7371: invalid format
  ```

### 3. Direct SSH on Port 22 (FAILED)
- **Method**: SSH TUN tunnel on port 22
- **Result**: Partially works then hangs. SSH key exchange completes but connection dies after encryption starts.
- **Evidence**:
  - Iran side: SSH handshake completes (KEXINIT, NEWKEYS all succeed), then hangs at `kex_input_ext_info: publickey-hostbound@openssh.com`
  - Kharej side: auth.log shows NO connection from Iran's IP, but shows HTTP probe floods (`GET / HTTP/1.1`) from Iran's IP on port 22
- **Conclusion**: ISP allows SSH handshake (for fingerprinting) but kills the connection once encryption starts. ISP also probes the server with HTTP simultaneously.

### 4. stunnel (SSH wrapped in TLS) on Port 443 (FAILED)
- **Method**: stunnel on Kharej (TLS server on :443 → localhost:22), stunnel on Iran (TLS client localhost:2222 → Kharej:443)
- **Result**: TLS handshake fails silently. No certificate returned.
- **Evidence**:
  ```bash
  # From Iran
  openssl s_client -connect 54.38.137.45:443 -quiet 2>/dev/null
  # Returns nothing — no TLS handshake, no certificate
  ```
- **Conclusion**: ISP transparent proxy on port 443 blocks non-browser TLS or blocks all TLS to this IP.

### 5. stunnel on Alternative Ports 8443/993/465/2083 (FAILED)
- **Method**: stunnel listening on multiple ports on Kharej
- **Result**: TCP RST injection. Connection established but immediately reset on TLS ClientHello.
- **Evidence**:
  ```
  Port 8443: write:errno=104 (ECONNRESET)
  Port 993:  write:errno=104 (ECONNRESET)
  Port 465:  write:errno=104 (ECONNRESET)
  Port 2083: write:errno=104 (ECONNRESET)
  ```
- **Conclusion**: ISP is likely **blacklisting the IP** `54.38.137.45` entirely, or doing deep packet inspection on all TLS connections to detected VPN server IPs.

---

## ISP DPI Behavior Summary

Iran's ISP implements multi-layer DPI:

| Layer | Behavior |
|-------|----------|
| **IP Protocol** | Blocks all non-TCP/UDP (GRE, IPIP, ICMP tunnels) |
| **Port 443** | Transparent HTTP proxy intercepts connections, sends `GET / HTTP/1.1` probes |
| **Port 22** | Allows SSH handshake for fingerprinting, then kills encrypted session |
| **TLS on any port** | TCP RST injection on TLS ClientHello to known VPN IPs |
| **IP blacklist** | Likely has `54.38.137.45` flagged as VPN/proxy server |

---

## What Works

- **ICMP ping**: Works fine (88ms latency Iran → Kharej)
- **TCP connect** (`nc -zv`): Works on all ports (SYN/ACK succeeds)
- **SSH from other IPs**: Kharej SSH works from non-Iran IPs
- **Iran SSH management**: Iran's own SSH on port 9011 works normally

---

## Current State of Servers

### Kharej has installed:
- **stunnel4**: Running, listening on ports 443, 8443, 993, 465, 2083
- **sshd config**: `PermitTunnel point-to-point`, `PermitRootLogin prohibit-password`, ports 22
- **IP forwarding**: Enabled (`net.ipv4.ip_forward=1`)
- **iptables**: NAT masquerade for 10.10.0.0/30, FORWARD rules for tun0, ports 443/8443/993/465/2083 allowed
- **x-ui (Xray)**: Installed at `/usr/local/x-ui/`
- **TLS cert**: Self-signed at `/etc/stunnel/stunnel.pem` (CN=cloudflare-dns.com)

### Iran has installed:
- **stunnel4**: Running, client mode, localhost:2222 → Kharej:443
- **SSH key**: `/root/.ssh/tunnel_key` (ed25519, public key added to Kharej authorized_keys)
- **SSH tunnel service**: `ssh-tunnel.service` (systemd, currently not working)
- **Tunnel script**: `/usr/local/bin/ssh-tunnel.sh`
- **Tunnel config**: `/etc/ssh-tunnel.conf`
- **iptables DNAT**: All TCP (except 22) → 10.10.0.1, All UDP → 10.10.0.1, MASQUERADE on tun0

### SSH Key (already deployed):
- **Private**: `/root/.ssh/tunnel_key` on Iran
- **Public**: Added to `/root/.ssh/authorized_keys` on Kharej (ssh-ed25519, comment: tunnel-key)
- **Key fingerprint**: `SHA256:7k+CGorMTPx8xJEJITT1mdcVQR1QYukwyu06c4KAtJg`

---

## Recommended Next Step: Xray REALITY

**Xray REALITY** is the only method likely to work given the ISP's aggressive DPI. It is specifically designed to bypass Iran's internet filtering.

### Why REALITY works:
- Makes the TLS handshake look like a connection to a **real legitimate website** (e.g., yahoo.com, google.com)
- Uses the **real website's TLS certificate** in the handshake (not self-signed)
- DPI cannot distinguish it from genuine HTTPS browsing
- The ISP would have to block yahoo.com/google.com to block REALITY (they won't)
- No IP blacklisting matters because the TLS fingerprint looks legitimate

### Architecture:
```
V2Ray User ──► Iran:PORT ──[Xray REALITY tunnel]──► Kharej (x-ui/Xray) ──► Internet
                                  │
                    ISP sees: normal HTTPS to yahoo.com
                    Uses yahoo.com's real TLS certificate
                    Cannot detect, cannot block
```

### Implementation Plan:

#### On Kharej (already has x-ui):
1. Access x-ui web panel
2. Create a new inbound with:
   - Protocol: **VLESS**
   - Transport: **TCP**
   - Security: **REALITY**
   - dest (target): `yahoo.com:443` (or another SNI)
   - serverNames: `yahoo.com`
   - Generate keypair (x25519 public/private key)
   - shortIds: generate random
   - Flow: `xtls-rprx-vision`
3. Note down: UUID, port, public key, shortId

#### On Iran:
1. Install Xray:
   ```bash
   bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
   ```
2. Configure Xray as transparent proxy/relay:
   - **Inbound**: `dokodemo-door` with `followRedirect: true` (accepts redirected traffic)
   - **Outbound**: `vless` with REALITY settings pointing to Kharej
   - **Routing**: Forward all traffic through VLESS outbound
3. iptables DNAT on Iran: redirect all incoming ports (except 22/9011) to Xray's dokodemo-door port
4. Create systemd service for Xray

#### Iran Xray config template:
```json
{
  "inbounds": [
    {
      "tag": "relay-in",
      "port": 12345,
      "protocol": "dokodemo-door",
      "settings": {
        "network": "tcp,udp",
        "followRedirect": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "to-kharej",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "54.38.137.45",
            "port": KHAREJ_REALITY_PORT,
            "users": [
              {
                "id": "GENERATED_UUID",
                "encryption": "none",
                "flow": "xtls-rprx-vision"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "yahoo.com",
          "fingerprint": "chrome",
          "publicKey": "KHAREJ_PUBLIC_KEY",
          "shortId": "KHAREJ_SHORT_ID"
        }
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": ["relay-in"],
        "outboundTag": "to-kharej"
      }
    ]
  }
}
```

#### Iran iptables for relay:
```bash
# Forward all incoming TCP (except SSH management) to Xray dokodemo-door
iptables -t nat -A PREROUTING -p tcp -d IRAN_PUBLIC_IP ! --dport 22 -j REDIRECT --to-port 12345
# Also exclude Iran's SSH management port 9011
iptables -t nat -A PREROUTING -p tcp -d IRAN_PUBLIC_IP --dport 9011 -j ACCEPT
# Note: the ACCEPT rule must come BEFORE the REDIRECT rule

# Forward UDP too
iptables -t nat -A PREROUTING -p udp -d IRAN_PUBLIC_IP -j REDIRECT --to-port 12345
```

---

## Cleanup Needed (before implementing REALITY)

### On Iran:
```bash
# Stop and remove old tunnel services
systemctl stop ssh-tunnel 2>/dev/null
systemctl disable ssh-tunnel 2>/dev/null
rm -f /etc/systemd/system/ssh-tunnel.service

# Stop stunnel (no longer needed)
systemctl stop stunnel4 2>/dev/null
systemctl disable stunnel4 2>/dev/null

# Clean iptables (remove old DNAT rules)
iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
iptables -F FORWARD

systemctl daemon-reload
```

### On Kharej:
```bash
# Stop stunnel (no longer needed)
systemctl stop stunnel4 2>/dev/null
systemctl disable stunnel4 2>/dev/null

# Clean extra iptables rules (keep NAT for tunnel subnet)
# Don't remove x-ui/Xray — we need it
```

---

## Current Solution: Xray REALITY + TLS Fragment

### Why This Works Against Iran DPI

The ISP's DPI has two main attack vectors:
1. **IP blacklisting** — Drops/resets all traffic to known VPN IPs
2. **TLS ClientHello inspection** — Injects TCP RST when it detects TLS handshake to suspicious IPs

Our solution defeats BOTH:

| Attack | Defense |
|--------|---------|
| IP blacklist | REALITY uses the **real TLS certificate** of a legitimate site (e.g., google.com). DPI sees a normal HTTPS connection. |
| ClientHello inspection | **TLS Fragment** splits the ClientHello into 10-100 byte chunks with delays. DPI can't reassemble fast enough to inspect. |
| Protocol fingerprinting | **Chrome uTLS** fingerprint makes the TLS look identical to a real Chrome browser. |
| DNS poisoning | **DNS-over-HTTPS** (1.1.1.1, 8.8.8.8) prevents DNS-level interference. |

### How TLS Fragment Works

```
Normal:    [------- ClientHello (517 bytes) -------] --> DPI inspects --> RST injected
Fragment:  [50b] --10ms-- [50b] --15ms-- [50b] ...  --> DPI timeout  --> PASSES
```

The DPI has a reassembly timeout. By sending tiny fragments with random delays,
the state machine overflows before it can match the signature.

### Architecture

```
V2Ray Client --> Iran:ANY_PORT --[iptables REDIRECT]--> Xray dokodemo-door :12345
                                                              |
                                                    [VLESS + REALITY + Fragment]
                                                              |
                                                     Kharej:443 (Xray REALITY)
                                                              |
                                                         Internet

ISP sees: Iran --> Cloudflare/Google IP:443 (normal HTTPS, fragmented handshake)
ISP cannot: Inspect ClientHello (fragmented), Detect protocol (Chrome uTLS), Block SNI (google.com)
```

### tunnel.sh Script Features

- **Setup**: One command per server (`bash tunnel.sh gateway` / `bash tunnel.sh relay`)
- **REALITY + Vision**: VLESS with xtls-rprx-vision flow for maximum performance
- **TLS Fragment**: Configurable fragmentation (aggressive/normal/ultra/custom)
- **Health Monitor**: systemd timer checks every 2 min, auto-restarts on failure
- **Live Tuning**: Change fragment/SNI settings without reinstalling
- **Diagnostics**: Built-in connectivity tests, log analysis, config validation
- **Safe iptables**: SSH management ports (9011, 22) always protected
- **DNS-over-HTTPS**: Prevents DNS-level censorship
- **SNI Scanner**: Tests which domains work best for REALITY disguise

## Files in This Repository

- `tunnel.sh` — Advanced Xray REALITY tunnel setup script with DPI evasion
- `setup.sh` — Old SSH+stunnel method (deprecated, blocked by DPI)
- `DOCUMENTATION.md` — This file
- `README.md` — Project readme

---

## Key Takeaways

1. **GRE/IPIP/SIT tunnels**: Dead on arrival. ISP blocks all non-TCP/UDP.
2. **Direct SSH**: Blocked by DPI on all ports. ISP fingerprints SSH protocol.
3. **stunnel/TLS**: Blocked. ISP either proxies port 443 or does TCP RST injection on other ports. The IP may be blacklisted.
4. **Xray REALITY**: The recommended solution. Purpose-built for this exact DPI environment. Uses legitimate website certificates to make traffic indistinguishable from normal HTTPS.
5. **Iran SSH management port is 9011** — must be excluded from any port forwarding rules.
