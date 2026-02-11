#!/bin/bash
#=============================================================================
#  Advanced Xray REALITY Tunnel with DPI Evasion
#
#  Purpose: Create a censorship-resistant tunnel between Iran (relay) and
#           Kharej (gateway) servers for V2Ray traffic relay.
#
#  DPI Evasion Features:
#    - VLESS + REALITY protocol (steals real TLS certs from legit sites)
#    - TLS ClientHello fragmentation (defeats RST injection on handshake)
#    - Chrome uTLS fingerprint (indistinguishable from real browser)
#    - DNS-over-HTTPS (prevents DNS poisoning/sniffing)
#    - Connection keepalive tuning (reduces re-handshakes)
#    - Multiple SNI fallback targets
#
#  Architecture:
#    Client --> Iran:ANY_PORT --[REALITY tunnel]--> Kharej (Xray) --> Internet
#                                |
#                  ISP sees: HTTPS to www.google.com
#                  Real Google TLS cert in handshake
#                  ClientHello fragmented (DPI can't inspect)
#
#  Usage:
#    Kharej:  bash tunnel.sh gateway
#    Iran:    bash tunnel.sh relay
#    Status:  bash tunnel.sh status
#    Diag:    bash tunnel.sh diagnose
#    Remove:  bash tunnel.sh uninstall
#=============================================================================

set -euo pipefail

# ── Colors & Formatting ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

log()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
error()  { echo -e "${RED}[x]${NC} $*"; }
info()   { echo -e "${CYAN}[i]${NC} $*"; }
header() {
    echo ""
    echo -e "${BOLD}================================================================${NC}"
    echo -e "${BOLD}  $*${NC}"
    echo -e "${BOLD}================================================================${NC}"
    echo ""
}

# ── Constants ──────────────────────────────────────────────────────────────
XRAY_INSTALL_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
XRAY_BIN="/usr/local/bin/xray"
CONFIG_DIR="/usr/local/etc/xray-tunnel"
LOG_DIR="/var/log/xray-tunnel"
SERVICE_NAME="xray-tunnel"
HEALTH_SCRIPT="/usr/local/bin/xray-tunnel-health.sh"

# Defaults
DEFAULT_TUNNEL_PORT=443
DEFAULT_SNI="www.google.com"
RELAY_LISTEN_PORT=12345

# Iran SSH management port - NEVER redirect this
IRAN_SSH_PORT=9011

# TLS Fragment defaults (aggressive for Iran DPI)
FRAG_LENGTH_AGGRESSIVE="10-100"
FRAG_INTERVAL_AGGRESSIVE="10-30"
FRAG_LENGTH_NORMAL="100-200"
FRAG_INTERVAL_NORMAL="10-20"

# ── Pre-flight Checks ─────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect OS"
        exit 1
    fi
    source /etc/os-release
    log "Detected OS: $PRETTY_NAME"

    if ! command -v curl &>/dev/null; then
        log "Installing curl..."
        apt-get update -qq && apt-get install -y -qq curl > /dev/null 2>&1
    fi
}

# ── Xray Installation ─────────────────────────────────────────────────────
install_xray() {
    if [[ -f "$XRAY_BIN" ]]; then
        local version
        version=$("$XRAY_BIN" version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
        log "Xray already installed (version: $version)"

        # Check minimum version for fragment support (1.8.0+)
        local major minor
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [[ "$major" -lt 1 ]] || { [[ "$major" -eq 1 ]] && [[ "$minor" -lt 8 ]]; }; then
            warn "Xray version $version is too old for fragment support"
            warn "Upgrading to latest..."
            bash -c "$(curl -sL $XRAY_INSTALL_URL)" @ install
        fi
        return 0
    fi

    log "Installing Xray core..."
    bash -c "$(curl -sL $XRAY_INSTALL_URL)" @ install

    if [[ ! -f "$XRAY_BIN" ]]; then
        error "Xray installation failed"
        exit 1
    fi

    # Disable the default xray service (we use our own)
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true

    local version
    version=$("$XRAY_BIN" version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    log "Xray $version installed successfully"
}

create_dirs() {
    mkdir -p "$CONFIG_DIR" "$LOG_DIR"
}

# ── Key Generation ─────────────────────────────────────────────────────────
generate_reality_keypair() {
    log "Generating x25519 keypair for REALITY..."
    local keypair
    keypair=$("$XRAY_BIN" x25519 2>&1) || true

    # Debug: show raw output if parsing fails
    PRIVATE_KEY=""
    PUBLIC_KEY=""

    # Try different output formats (varies by Xray version)
    # Format 1 (v26+): "PrivateKey:xxx" / "PublicKey:xxx" (no space)
    # Format 2 (older): "Private key: xxx" / "Public key: xxx" (with space)
    local priv_line pub_line
    priv_line=$(echo "$keypair" | grep -i "private" || true)
    pub_line=$(echo "$keypair" | grep -i "public" || true)

    if [[ -n "$priv_line" ]]; then
        # Strip label — handles "PrivateKey:VALUE" and "Private key: VALUE"
        PRIVATE_KEY=$(echo "$priv_line" | awk -F'[: ]+' '{print $NF}' | tr -d '[:space:]')
        # Fallback: strip everything before and including first colon
        if echo "$PRIVATE_KEY" | grep -qi "key"; then
            PRIVATE_KEY=$(echo "$priv_line" | rev | cut -d: -f1 | rev | tr -d '[:space:]')
        fi
    fi
    if [[ -n "$pub_line" ]]; then
        PUBLIC_KEY=$(echo "$pub_line" | awk -F'[: ]+' '{print $NF}' | tr -d '[:space:]')
        if echo "$PUBLIC_KEY" | grep -qi "key"; then
            PUBLIC_KEY=$(echo "$pub_line" | rev | cut -d: -f1 | rev | tr -d '[:space:]')
        fi
    fi

    # Format 3: First line = private, second line = public (no labels)
    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        local line1 line2
        line1=$(echo "$keypair" | sed -n '1p' | tr -d '[:space:]')
        line2=$(echo "$keypair" | sed -n '2p' | tr -d '[:space:]')
        if [[ ${#line1} -gt 20 && ${#line2} -gt 20 ]]; then
            PRIVATE_KEY="$line1"
            PUBLIC_KEY="$line2"
        fi
    fi

    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        error "Failed to generate x25519 keypair"
        error "Raw xray x25519 output:"
        echo "$keypair"
        error "Please report this output format"
        exit 1
    fi

    log "Keypair generated successfully"
}

generate_uuid() {
    UUID=$("$XRAY_BIN" uuid 2>/dev/null) || true
    if [[ -z "$UUID" ]]; then
        UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null) || true
    fi
    if [[ -z "$UUID" ]]; then
        UUID=$(uuidgen 2>/dev/null) || true
    fi
    if [[ -z "$UUID" ]]; then
        error "Failed to generate UUID"
        exit 1
    fi
    log "UUID generated"
}

generate_short_id() {
    SHORT_ID=$(openssl rand -hex 8 2>/dev/null) || true
    if [[ -z "$SHORT_ID" ]]; then
        SHORT_ID=$(head -c 8 /dev/urandom | xxd -p 2>/dev/null) || true
    fi
    if [[ -z "$SHORT_ID" ]]; then
        error "Failed to generate Short ID"
        exit 1
    fi
    log "Short ID generated"
}

# ── SNI Validation ─────────────────────────────────────────────────────────
validate_sni() {
    local sni="$1"
    log "Validating SNI target: $sni ..."

    # Skip validation if openssl or timeout not available
    if ! command -v openssl &>/dev/null; then
        warn "openssl not found, skipping SNI validation"
        return 0
    fi

    local result=""
    result=$(echo "" | timeout 10 openssl s_client -connect "$sni:443" -tls1_3 -alpn h2 2>/dev/null) || true

    local tls13=0 h2=0
    tls13=$(echo "$result" | grep -c "TLSv1.3") || true
    h2=$(echo "$result" | grep -c "h2") || true

    if [[ $tls13 -gt 0 && $h2 -gt 0 ]]; then
        log "$sni: TLS 1.3 + H2 supported (ideal)"
        return 0
    elif [[ $tls13 -gt 0 ]]; then
        warn "$sni: TLS 1.3 OK but no H2 (acceptable)"
        return 0
    else
        warn "$sni: Could not verify TLS 1.3 (may still work)"
        return 1
    fi
}

# ══════════════════════════════════════════════════════════════════════════
#  KHAREJ (GATEWAY) SETUP
# ══════════════════════════════════════════════════════════════════════════
setup_gateway() {
    header "KHAREJ (Gateway) Server Setup"

    check_root
    check_os
    install_xray
    create_dirs

    # ── Generate cryptographic material ──
    generate_reality_keypair
    generate_uuid
    generate_short_id

    echo ""
    info "Generated credentials:"
    info "  UUID:        $UUID"
    info "  Public Key:  $PUBLIC_KEY"
    info "  Private Key: ${PRIVATE_KEY:0:8}... (hidden)"
    info "  Short ID:    $SHORT_ID"

    # ── Configure tunnel port ──
    echo ""
    read -rp "$(echo -e "${CYAN}Tunnel port [${DEFAULT_TUNNEL_PORT}]: ${NC}")" TUNNEL_PORT
    TUNNEL_PORT=${TUNNEL_PORT:-$DEFAULT_TUNNEL_PORT}

    # Check if port is already in use by x-ui or something else
    if ss -tlnp | grep -q ":${TUNNEL_PORT} " 2>/dev/null; then
        local proc
        proc=$(ss -tlnp | grep ":${TUNNEL_PORT} " | head -1)
        warn "Port $TUNNEL_PORT is already in use:"
        warn "  $proc"
        read -rp "$(echo -e "${YELLOW}Choose a different port: ${NC}")" TUNNEL_PORT
    fi

    # ── Select SNI target ──
    echo ""
    info "SNI target selection (the website REALITY will impersonate):"
    info "  Requirements: Must support TLS 1.3 + H2"
    echo ""
    echo "  1) www.google.com     (most tested, recommended)"
    echo "  2) dl.google.com      (looks like download traffic)"
    echo "  3) www.microsoft.com  (enterprise traffic)"
    echo "  4) www.samsung.com    (consumer traffic)"
    echo "  5) speed.cloudflare.com"
    echo "  6) Custom"
    echo ""
    read -rp "$(echo -e "${CYAN}Choose SNI [1]: ${NC}")" sni_choice
    case ${sni_choice:-1} in
        1) SNI="www.google.com" ;;
        2) SNI="dl.google.com" ;;
        3) SNI="www.microsoft.com" ;;
        4) SNI="www.samsung.com" ;;
        5) SNI="speed.cloudflare.com" ;;
        6) read -rp "Enter custom SNI domain: " SNI ;;
        *) SNI="www.google.com" ;;
    esac

    validate_sni "$SNI" || {
        warn "SNI validation failed. Continuing anyway (may not work)."
    }

    # ── Write Xray config ──
    log "Writing gateway config..."
    cat > "$CONFIG_DIR/config.json" << GEOF
{
    "log": {
        "loglevel": "warning",
        "access": "${LOG_DIR}/access.log",
        "error": "${LOG_DIR}/error.log"
    },
    "inbounds": [
        {
            "tag": "reality-in",
            "listen": "0.0.0.0",
            "port": ${TUNNEL_PORT},
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${UUID}",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "${SNI}:443",
                    "xver": 0,
                    "serverNames": [
                        "${SNI}"
                    ],
                    "privateKey": "${PRIVATE_KEY}",
                    "shortIds": [
                        "${SHORT_ID}",
                        ""
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom"
        },
        {
            "tag": "block",
            "protocol": "blackhole"
        }
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "outboundTag": "block",
                "protocol": [
                    "bittorrent"
                ]
            }
        ]
    }
}
GEOF

    # Validate config
    log "Validating config..."
    if ! "$XRAY_BIN" run -test -config "$CONFIG_DIR/config.json" 2>/dev/null; then
        error "Config validation failed:"
        "$XRAY_BIN" run -test -config "$CONFIG_DIR/config.json" 2>&1
        exit 1
    fi
    log "Config valid"

    # ── Create systemd service ──
    log "Creating systemd service..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << SEOF
[Unit]
Description=Xray REALITY Tunnel (Gateway)
Documentation=https://xtls.github.io
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${XRAY_BIN} run -config ${CONFIG_DIR}/config.json
Restart=always
RestartSec=3
LimitNOFILE=65535
LimitNPROC=65535
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SEOF

    # ── Firewall ──
    log "Configuring firewall..."
    if command -v ufw &>/dev/null; then
        ufw allow "$TUNNEL_PORT"/tcp 2>/dev/null || true
    fi
    iptables -C INPUT -p tcp --dport "$TUNNEL_PORT" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p tcp --dport "$TUNNEL_PORT" -j ACCEPT

    # ── Log rotation ──
    cat > /etc/logrotate.d/xray-tunnel << LEOF
${LOG_DIR}/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
LEOF

    # ── Start service ──
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" 2>/dev/null
    systemctl restart "$SERVICE_NAME"

    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Gateway service started successfully"
    else
        error "Service failed to start!"
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager
        exit 1
    fi

    # ── Detect public IP ──
    GATEWAY_IP=$(curl -s4 --max-time 5 ifconfig.me || curl -s4 --max-time 5 icanhazip.com || echo "UNKNOWN")

    # ── Save connection info ──
    cat > "$CONFIG_DIR/connection-info.env" << CEOF
# Xray REALITY Tunnel - Connection Info
# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
# KEEP THIS FILE SECURE - contains tunnel credentials
GATEWAY_IP=${GATEWAY_IP}
TUNNEL_PORT=${TUNNEL_PORT}
UUID=${UUID}
PUBLIC_KEY=${PUBLIC_KEY}
PRIVATE_KEY=${PRIVATE_KEY}
SHORT_ID=${SHORT_ID}
SNI=${SNI}
CEOF
    chmod 600 "$CONFIG_DIR/connection-info.env"

    # ── Output ──
    header "GATEWAY SETUP COMPLETE"
    echo -e "${GREEN}Save these values - you need them for Iran relay setup:${NC}"
    echo ""
    echo -e "  ${BOLD}Gateway IP:${NC}    $GATEWAY_IP"
    echo -e "  ${BOLD}Port:${NC}          $TUNNEL_PORT"
    echo -e "  ${BOLD}UUID:${NC}          $UUID"
    echo -e "  ${BOLD}Public Key:${NC}    $PUBLIC_KEY"
    echo -e "  ${BOLD}Short ID:${NC}      $SHORT_ID"
    echo -e "  ${BOLD}SNI:${NC}           $SNI"
    echo ""
    echo -e "${YELLOW}Run this on Iran server:${NC}"
    echo ""
    echo -e "  bash tunnel.sh relay \\"
    echo -e "    --gw-ip ${GATEWAY_IP} \\"
    echo -e "    --gw-port ${TUNNEL_PORT} \\"
    echo -e "    --uuid ${UUID} \\"
    echo -e "    --pubkey ${PUBLIC_KEY} \\"
    echo -e "    --shortid ${SHORT_ID} \\"
    echo -e "    --sni ${SNI}"
    echo ""
    info "Connection info saved to: $CONFIG_DIR/connection-info.env"
    info "Service status: systemctl status $SERVICE_NAME"
    info "Live logs: journalctl -u $SERVICE_NAME -f"
}

# ══════════════════════════════════════════════════════════════════════════
#  IRAN (RELAY) SETUP
# ══════════════════════════════════════════════════════════════════════════
setup_relay() {
    header "IRAN (Relay) Server Setup"

    check_root
    check_os

    # ── Collect gateway connection info ──
    if [[ -z "${GW_IP:-}" ]]; then
        echo -e "${CYAN}Enter connection details from Kharej gateway setup:${NC}"
        echo ""
        read -rp "  Gateway IP: " GW_IP
        read -rp "  Gateway Port [${DEFAULT_TUNNEL_PORT}]: " GW_PORT
        GW_PORT=${GW_PORT:-$DEFAULT_TUNNEL_PORT}
        read -rp "  UUID: " GW_UUID
        read -rp "  Public Key: " GW_PUBKEY
        read -rp "  Short ID: " GW_SHORTID
        read -rp "  SNI [${DEFAULT_SNI}]: " GW_SNI
        GW_SNI=${GW_SNI:-$DEFAULT_SNI}
    fi

    # Validate required fields
    local missing=0
    [[ -z "${GW_IP:-}" ]]      && { error "Gateway IP is required"; missing=1; }
    [[ -z "${GW_UUID:-}" ]]    && { error "UUID is required"; missing=1; }
    [[ -z "${GW_PUBKEY:-}" ]]  && { error "Public Key is required"; missing=1; }
    [[ -z "${GW_SHORTID:-}" ]] && { error "Short ID is required"; missing=1; }
    [[ $missing -eq 1 ]] && exit 1

    GW_PORT=${GW_PORT:-$DEFAULT_TUNNEL_PORT}
    GW_SNI=${GW_SNI:-$DEFAULT_SNI}

    echo ""
    info "Gateway target: $GW_IP:$GW_PORT"
    info "REALITY SNI:    $GW_SNI"
    info "UUID:           ${GW_UUID:0:8}..."

    # ── TLS Fragment mode ──
    echo ""
    info "TLS Fragment mode (how aggressively to split TLS ClientHello):"
    echo ""
    echo "  1) Aggressive  - length=10-100, interval=10-30ms (recommended for Iran)"
    echo "  2) Normal       - length=100-200, interval=10-20ms"
    echo "  3) Ultra        - length=1-50, interval=20-50ms (maximum fragmentation)"
    echo "  4) Custom"
    echo ""
    read -rp "$(echo -e "${CYAN}Fragment mode [1]: ${NC}")" frag_mode
    case ${frag_mode:-1} in
        1)
            FRAG_LENGTH="$FRAG_LENGTH_AGGRESSIVE"
            FRAG_INTERVAL="$FRAG_INTERVAL_AGGRESSIVE"
            ;;
        2)
            FRAG_LENGTH="$FRAG_LENGTH_NORMAL"
            FRAG_INTERVAL="$FRAG_INTERVAL_NORMAL"
            ;;
        3)
            FRAG_LENGTH="1-50"
            FRAG_INTERVAL="20-50"
            ;;
        4)
            read -rp "  Fragment length (e.g. 10-100): " FRAG_LENGTH
            read -rp "  Fragment interval ms (e.g. 10-30): " FRAG_INTERVAL
            ;;
        *)
            FRAG_LENGTH="$FRAG_LENGTH_AGGRESSIVE"
            FRAG_INTERVAL="$FRAG_INTERVAL_AGGRESSIVE"
            ;;
    esac

    log "Fragment: length=$FRAG_LENGTH, interval=${FRAG_INTERVAL}ms"

    # ── Cleanup old tunnel infrastructure ──
    header "Cleaning Up Old Tunnel Configs"
    cleanup_old_tunnel

    # ── Install Xray ──
    install_xray
    create_dirs

    # ── Write Xray relay config ──
    # NOTE: flow xtls-rprx-vision is INCOMPATIBLE with mux
    # Fragment in sockopt handles DPI evasion without mux
    log "Writing relay config..."
    cat > "$CONFIG_DIR/config.json" << REOF
{
    "log": {
        "loglevel": "warning",
        "access": "${LOG_DIR}/access.log",
        "error": "${LOG_DIR}/error.log"
    },
    "dns": {
        "servers": [
            {
                "address": "https+local://1.1.1.1/dns-query",
                "skipFallback": true
            },
            {
                "address": "https+local://8.8.8.8/dns-query",
                "skipFallback": false
            }
        ],
        "queryStrategy": "UseIPv4"
    },
    "inbounds": [
        {
            "tag": "relay-in",
            "listen": "0.0.0.0",
            "port": ${RELAY_LISTEN_PORT},
            "protocol": "dokodemo-door",
            "settings": {
                "network": "tcp,udp",
                "followRedirect": true
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ],
                "routeOnly": true
            }
        }
    ],
    "outbounds": [
        {
            "tag": "tunnel-out",
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "${GW_IP}",
                        "port": ${GW_PORT},
                        "users": [
                            {
                                "id": "${GW_UUID}",
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
                    "serverName": "${GW_SNI}",
                    "fingerprint": "chrome",
                    "publicKey": "${GW_PUBKEY}",
                    "shortId": "${GW_SHORTID}",
                    "spiderX": ""
                },
                "sockopt": {
                    "tcpNoDelay": true,
                    "tcpKeepAliveIdle": 100,
                    "fragment": {
                        "packets": "tlshello",
                        "length": "${FRAG_LENGTH}",
                        "interval": "${FRAG_INTERVAL}"
                    }
                }
            }
        },
        {
            "tag": "direct",
            "protocol": "freedom"
        },
        {
            "tag": "block",
            "protocol": "blackhole"
        }
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "inboundTag": [
                    "relay-in"
                ],
                "outboundTag": "tunnel-out"
            }
        ]
    }
}
REOF

    # Validate config
    log "Validating config..."
    if ! "$XRAY_BIN" run -test -config "$CONFIG_DIR/config.json" 2>/dev/null; then
        error "Config validation failed:"
        "$XRAY_BIN" run -test -config "$CONFIG_DIR/config.json" 2>&1
        exit 1
    fi
    log "Config valid"

    # ── Create systemd service ──
    log "Creating systemd service..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << SEOF
[Unit]
Description=Xray REALITY Tunnel (Relay)
Documentation=https://xtls.github.io
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${XRAY_BIN} run -config ${CONFIG_DIR}/config.json
Restart=always
RestartSec=3
LimitNOFILE=65535
LimitNPROC=65535
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SEOF

    # ── iptables relay rules ──
    setup_relay_iptables

    # ── Log rotation ──
    cat > /etc/logrotate.d/xray-tunnel << LEOF
${LOG_DIR}/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
LEOF

    # ── Start service ──
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" 2>/dev/null
    systemctl restart "$SERVICE_NAME"

    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Relay service started successfully"
    else
        error "Service failed to start!"
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager
        exit 1
    fi

    # ── Health monitoring ──
    setup_health_monitor

    # ── Connectivity test ──
    header "Testing Tunnel"
    test_tunnel_connectivity

    # ── Output ──
    header "IRAN RELAY SETUP COMPLETE"
    echo -e "  ${BOLD}Relay listen:${NC}   0.0.0.0:$RELAY_LISTEN_PORT (dokodemo-door)"
    echo -e "  ${BOLD}Gateway:${NC}        $GW_IP:$GW_PORT"
    echo -e "  ${BOLD}Protocol:${NC}       VLESS + REALITY + xtls-rprx-vision"
    echo -e "  ${BOLD}SNI disguise:${NC}   $GW_SNI"
    echo -e "  ${BOLD}Fragment:${NC}       length=$FRAG_LENGTH, interval=${FRAG_INTERVAL}ms"
    echo -e "  ${BOLD}Fingerprint:${NC}    Chrome (uTLS)"
    echo -e "  ${BOLD}DNS:${NC}            DoH (1.1.1.1 + 8.8.8.8)"
    echo ""
    echo -e "  ${GREEN}Service:${NC}    systemctl status $SERVICE_NAME"
    echo -e "  ${GREEN}Logs:${NC}       journalctl -u $SERVICE_NAME -f"
    echo -e "  ${GREEN}Health:${NC}     systemctl status xray-tunnel-health.timer"
    echo -e "  ${GREEN}Diagnose:${NC}   bash tunnel.sh diagnose"
    echo ""
    echo -e "  ${YELLOW}iptables redirects ALL incoming TCP/UDP (except SSH) to Xray${NC}"
    echo -e "  ${YELLOW}Protected ports: $IRAN_SSH_PORT (SSH management), 22${NC}"
}

# ── Cleanup old tunnel configs on Iran ─────────────────────────────────────
cleanup_old_tunnel() {
    log "Stopping old services..."

    # Stop old tunnel services
    for svc in ssh-tunnel stunnel4 xray-tunnel xray; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            warn "Stopping $svc..."
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
        fi
    done

    # Remove old service files
    rm -f /etc/systemd/system/ssh-tunnel.service

    # Flush old iptables NAT rules
    log "Flushing old iptables NAT rules..."
    iptables -t nat -F PREROUTING 2>/dev/null || true
    iptables -t nat -F POSTROUTING 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true

    systemctl daemon-reload
    log "Old configs cleaned"
}

# ── iptables setup for Iran relay ──────────────────────────────────────────
setup_relay_iptables() {
    log "Configuring iptables for traffic relay..."

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    # Flush NAT PREROUTING (we manage it completely)
    iptables -t nat -F PREROUTING 2>/dev/null || true

    # RULE ORDER MATTERS - ACCEPT rules MUST come before REDIRECT

    # 1. Protect SSH management port (NEVER redirect)
    iptables -t nat -A PREROUTING -p tcp --dport "$IRAN_SSH_PORT" -j ACCEPT
    log "  Protected: TCP port $IRAN_SSH_PORT (SSH management)"

    # 2. Protect port 22 (fallback SSH)
    iptables -t nat -A PREROUTING -p tcp --dport 22 -j ACCEPT
    log "  Protected: TCP port 22 (SSH fallback)"

    # 3. Protect Xray relay port from being redirected to itself
    iptables -t nat -A PREROUTING -p tcp --dport "$RELAY_LISTEN_PORT" -j ACCEPT
    log "  Protected: TCP port $RELAY_LISTEN_PORT (Xray listen)"

    # 4. Redirect ALL other TCP to Xray dokodemo-door
    iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port "$RELAY_LISTEN_PORT"
    log "  Redirect: All other TCP -> :$RELAY_LISTEN_PORT"

    # 5. Redirect ALL UDP to Xray dokodemo-door
    iptables -t nat -A PREROUTING -p udp -j REDIRECT --to-port "$RELAY_LISTEN_PORT"
    log "  Redirect: All UDP -> :$RELAY_LISTEN_PORT"

    # Persist rules across reboots
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
        log "iptables rules saved (netfilter-persistent)"
    else
        # Install iptables-persistent for auto-restore
        log "Installing iptables-persistent for rule persistence..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent > /dev/null 2>&1 || {
            warn "Could not install iptables-persistent"
            warn "Rules will not survive reboot. Run: apt install iptables-persistent"
        }
        netfilter-persistent save 2>/dev/null || true
    fi

    log "iptables relay rules configured"
}

# ── Health monitoring ──────────────────────────────────────────────────────
setup_health_monitor() {
    log "Setting up health monitoring..."

    cat > "$HEALTH_SCRIPT" << 'HEOF'
#!/bin/bash
# Xray Tunnel Health Monitor
# Checks service health, restarts if needed, logs issues

SERVICE="xray-tunnel"
LOG="/var/log/xray-tunnel/health.log"
MAX_RESTARTS=5
RESTART_COUNT_FILE="/tmp/xray-tunnel-restart-count"
LAST_RESET_FILE="/tmp/xray-tunnel-restart-reset"

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

# Reset counter every hour
now=$(date +%s)
last_reset=$(cat "$LAST_RESET_FILE" 2>/dev/null || echo 0)
if (( now - last_reset > 3600 )); then
    echo 0 > "$RESTART_COUNT_FILE"
    echo "$now" > "$LAST_RESET_FILE"
fi

# Check 1: Is the service running?
if ! systemctl is-active --quiet "$SERVICE"; then
    echo "$(timestamp) [HEALTH] Service DOWN - attempting restart" >> "$LOG"

    count=$(cat "$RESTART_COUNT_FILE" 2>/dev/null || echo 0)
    count=$((count + 1))
    echo "$count" > "$RESTART_COUNT_FILE"

    if (( count <= MAX_RESTARTS )); then
        systemctl restart "$SERVICE"
        sleep 2
        if systemctl is-active --quiet "$SERVICE"; then
            echo "$(timestamp) [HEALTH] Restart #$count successful" >> "$LOG"
        else
            echo "$(timestamp) [HEALTH] Restart #$count FAILED" >> "$LOG"
        fi
    else
        echo "$(timestamp) [CRITICAL] $count restarts in 1 hour - possible DPI blocking" >> "$LOG"
        echo "$(timestamp) [CRITICAL] Try: bash tunnel.sh diagnose" >> "$LOG"
    fi
    exit 0
fi

# Check 2: Is Xray process actually listening?
if ! ss -tlnp | grep -q "xray" 2>/dev/null; then
    echo "$(timestamp) [HEALTH] Xray running but not listening - restarting" >> "$LOG"
    systemctl restart "$SERVICE"
fi

# Check 3: Log file size management
for logfile in /var/log/xray-tunnel/*.log; do
    if [[ -f "$logfile" ]]; then
        size=$(stat -f%z "$logfile" 2>/dev/null || stat -c%s "$logfile" 2>/dev/null || echo 0)
        if (( size > 104857600 )); then  # 100MB
            echo "$(timestamp) [HEALTH] Truncating oversized log: $logfile" >> "$LOG"
            tail -1000 "$logfile" > "${logfile}.tmp" && mv "${logfile}.tmp" "$logfile"
        fi
    fi
done
HEOF
    chmod +x "$HEALTH_SCRIPT"

    # Systemd oneshot service for health check
    cat > "/etc/systemd/system/xray-tunnel-health.service" << HSEOF
[Unit]
Description=Xray Tunnel Health Check

[Service]
Type=oneshot
ExecStart=${HEALTH_SCRIPT}
HSEOF

    # Timer: run every 2 minutes
    cat > "/etc/systemd/system/xray-tunnel-health.timer" << HTEOF
[Unit]
Description=Xray Tunnel Health Check Timer

[Timer]
OnBootSec=60
OnUnitActiveSec=120
AccuracySec=30

[Install]
WantedBy=timers.target
HTEOF

    systemctl daemon-reload
    systemctl enable xray-tunnel-health.timer 2>/dev/null
    systemctl start xray-tunnel-health.timer

    log "Health monitor active (every 2 minutes)"
}

# ── Tunnel connectivity test ───────────────────────────────────────────────
test_tunnel_connectivity() {
    log "Testing TCP connectivity to gateway $GW_IP:$GW_PORT..."

    if timeout 5 bash -c "echo >/dev/tcp/$GW_IP/$GW_PORT" 2>/dev/null; then
        log "TCP connect to $GW_IP:$GW_PORT: SUCCESS"
    else
        warn "TCP connect to $GW_IP:$GW_PORT: FAILED (expected if IP is filtered)"
        info "This does NOT mean the tunnel won't work!"
        info "TLS fragment splits the handshake to bypass DPI RST injection"
        info "The tunnel may establish successfully despite failed raw TCP test"
    fi

    # Check Xray logs for errors
    sleep 3
    if [[ -f "$LOG_DIR/error.log" ]]; then
        local errors
        errors=$(grep -c "failed\|error\|rejected" "$LOG_DIR/error.log" 2>/dev/null || echo 0)
        if [[ "$errors" -gt 0 ]]; then
            warn "Found $errors errors in Xray log:"
            tail -5 "$LOG_DIR/error.log"
        else
            log "No errors in Xray log"
        fi
    fi

    # Check if service is stable
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Service is running and stable"
    else
        error "Service crashed during test!"
        journalctl -u "$SERVICE_NAME" -n 10 --no-pager
    fi
}

# ══════════════════════════════════════════════════════════════════════════
#  STATUS / DIAGNOSTICS / UTILITIES
# ══════════════════════════════════════════════════════════════════════════

show_status() {
    header "Xray Tunnel Status"

    # Service status
    echo -e "${BOLD}[Service]${NC}"
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log "Status: RUNNING"
        local pid uptime_info
        pid=$(systemctl show "$SERVICE_NAME" -p MainPID --value 2>/dev/null || echo "?")
        uptime_info=$(systemctl show "$SERVICE_NAME" -p ActiveEnterTimestamp --value 2>/dev/null || echo "?")
        info "  PID: $pid"
        info "  Since: $uptime_info"
    else
        error "Status: STOPPED"
    fi

    # Config info
    echo ""
    echo -e "${BOLD}[Config]${NC}"
    if [[ -f "$CONFIG_DIR/config.json" ]]; then
        if grep -q "dokodemo-door" "$CONFIG_DIR/config.json" 2>/dev/null; then
            info "  Role: RELAY (Iran)"
            local gw_ip gw_port frag_len frag_int
            gw_ip=$(grep -o '"address": "[^"]*"' "$CONFIG_DIR/config.json" | head -1 | cut -d'"' -f4)
            gw_port=$(grep -o '"port": [0-9]*' "$CONFIG_DIR/config.json" | sed -n '2p' | awk '{print $2}')
            frag_len=$(grep -o '"length": "[^"]*"' "$CONFIG_DIR/config.json" | cut -d'"' -f4)
            frag_int=$(grep -o '"interval": "[^"]*"' "$CONFIG_DIR/config.json" | cut -d'"' -f4)
            info "  Gateway: $gw_ip:$gw_port"
            info "  Fragment: length=$frag_len interval=$frag_int"
        else
            info "  Role: GATEWAY (Kharej)"
            local port
            port=$(grep -o '"port": [0-9]*' "$CONFIG_DIR/config.json" | head -1 | awk '{print $2}')
            info "  Listen port: $port"
        fi
    else
        warn "  No config found at $CONFIG_DIR/config.json"
    fi

    # Listening ports
    echo ""
    echo -e "${BOLD}[Listening]${NC}"
    ss -tlnp 2>/dev/null | grep xray || warn "  Xray not listening"

    # iptables NAT
    echo ""
    echo -e "${BOLD}[iptables NAT PREROUTING]${NC}"
    iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null || warn "  No NAT rules"

    # Health timer
    echo ""
    echo -e "${BOLD}[Health Monitor]${NC}"
    if systemctl is-active --quiet xray-tunnel-health.timer 2>/dev/null; then
        log "Health timer: ACTIVE"
        local next_run
        next_run=$(systemctl show xray-tunnel-health.timer -p NextElapseUSecRealtime --value 2>/dev/null || echo "?")
        info "  Next check: $next_run"
    else
        warn "Health timer: INACTIVE"
    fi

    # Recent logs
    echo ""
    echo -e "${BOLD}[Recent Logs (last 10 lines)]${NC}"
    journalctl -u "$SERVICE_NAME" -n 10 --no-pager 2>/dev/null || warn "  No logs"
}

diagnose() {
    header "Tunnel Diagnostics"

    if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
        error "No config found. Run setup first: bash tunnel.sh gateway|relay"
        exit 1
    fi

    local role
    if grep -q "dokodemo-door" "$CONFIG_DIR/config.json" 2>/dev/null; then
        role="relay"
    else
        role="gateway"
    fi
    log "Role: $role"

    # 1. Config validation
    echo ""
    echo -e "${BOLD}[1] Config Validation${NC}"
    if "$XRAY_BIN" run -test -config "$CONFIG_DIR/config.json" 2>/dev/null; then
        log "Config: VALID"
    else
        error "Config: INVALID"
        "$XRAY_BIN" run -test -config "$CONFIG_DIR/config.json" 2>&1 | tail -5
    fi

    # 2. Service check
    echo ""
    echo -e "${BOLD}[2] Service Status${NC}"
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Service: RUNNING"
    else
        error "Service: DOWN"
        echo "  Last 5 log lines:"
        journalctl -u "$SERVICE_NAME" -n 5 --no-pager 2>/dev/null
    fi

    # 3. Port check
    echo ""
    echo -e "${BOLD}[3] Port Binding${NC}"
    local xray_ports
    xray_ports=$(ss -tlnp 2>/dev/null | grep xray || true)
    if [[ -n "$xray_ports" ]]; then
        log "Xray listening:"
        echo "  $xray_ports"
    else
        error "Xray NOT listening on any port"
    fi

    # 4. Relay-specific checks
    if [[ "$role" == "relay" ]]; then
        echo ""
        echo -e "${BOLD}[4] iptables NAT Rules${NC}"
        local nat_rules
        nat_rules=$(iptables -t nat -L PREROUTING -n 2>/dev/null || true)
        echo "$nat_rules"

        # Check SSH protection
        if echo "$nat_rules" | grep -q "dpt:$IRAN_SSH_PORT.*ACCEPT"; then
            log "SSH port $IRAN_SSH_PORT: PROTECTED"
        else
            error "SSH port $IRAN_SSH_PORT: NOT PROTECTED (dangerous!)"
        fi

        echo ""
        echo -e "${BOLD}[5] Gateway Connectivity${NC}"
        local gw_ip gw_port
        gw_ip=$(grep -o '"address": "[^"]*"' "$CONFIG_DIR/config.json" | head -1 | cut -d'"' -f4)
        gw_port=$(grep -o '"port": [0-9]*' "$CONFIG_DIR/config.json" | sed -n '2p' | awk '{print $2}')

        if [[ -n "$gw_ip" && -n "$gw_port" ]]; then
            # ICMP ping
            if ping -c 2 -W 3 "$gw_ip" > /dev/null 2>&1; then
                log "ICMP ping to $gw_ip: OK"
            else
                warn "ICMP ping to $gw_ip: FAILED"
            fi

            # TCP connect
            if timeout 5 bash -c "echo >/dev/tcp/$gw_ip/$gw_port" 2>/dev/null; then
                log "TCP connect to $gw_ip:$gw_port: OK"
            else
                warn "TCP connect to $gw_ip:$gw_port: BLOCKED"
                info "  (Expected if ISP blocks direct connections)"
                info "  TLS fragment should bypass this"
            fi

            # DNS resolution test
            if timeout 5 bash -c "echo >/dev/tcp/1.1.1.1/443" 2>/dev/null; then
                log "DNS-over-HTTPS (1.1.1.1): REACHABLE"
            else
                warn "DNS-over-HTTPS (1.1.1.1): BLOCKED"
            fi
        fi

        echo ""
        echo -e "${BOLD}[6] Error Log Analysis${NC}"
        if [[ -f "$LOG_DIR/error.log" ]]; then
            local total_errors
            total_errors=$(wc -l < "$LOG_DIR/error.log" 2>/dev/null || echo 0)
            info "Total log lines: $total_errors"

            # Common error patterns
            local tls_errors conn_errors auth_errors
            tls_errors=$(grep -c "tls.*failed\|handshake.*failed\|reality.*failed" "$LOG_DIR/error.log" 2>/dev/null || echo 0)
            conn_errors=$(grep -c "connection.*refused\|dial.*failed\|timeout" "$LOG_DIR/error.log" 2>/dev/null || echo 0)
            auth_errors=$(grep -c "authentication\|invalid.*user\|rejected" "$LOG_DIR/error.log" 2>/dev/null || echo 0)

            if [[ $tls_errors -gt 0 ]]; then
                warn "TLS/REALITY errors: $tls_errors (DPI may be interfering)"
            fi
            if [[ $conn_errors -gt 0 ]]; then
                warn "Connection errors: $conn_errors (gateway unreachable or blocked)"
            fi
            if [[ $auth_errors -gt 0 ]]; then
                error "Auth errors: $auth_errors (check UUID/keys match gateway)"
            fi

            if [[ $tls_errors -eq 0 && $conn_errors -eq 0 && $auth_errors -eq 0 ]]; then
                log "No concerning error patterns found"
            fi

            echo ""
            info "Last 10 error lines:"
            tail -10 "$LOG_DIR/error.log" 2>/dev/null
        else
            info "No error log yet"
        fi

        echo ""
        echo -e "${BOLD}[7] Health Monitor${NC}"
        if [[ -f "$LOG_DIR/health.log" ]]; then
            info "Recent health events:"
            tail -5 "$LOG_DIR/health.log" 2>/dev/null
        else
            info "No health events logged"
        fi
    fi

    # Gateway-specific checks
    if [[ "$role" == "gateway" ]]; then
        echo ""
        echo -e "${BOLD}[4] Connection Info${NC}"
        if [[ -f "$CONFIG_DIR/connection-info.env" ]]; then
            log "Connection info file exists"
            grep -v "PRIVATE_KEY" "$CONFIG_DIR/connection-info.env" | grep -v "^#"
        else
            warn "No connection info file (was setup completed?)"
        fi
    fi
}

# ── SNI Scanner ────────────────────────────────────────────────────────────
scan_sni() {
    header "SNI Scanner - Finding Best REALITY Targets"
    info "Testing domains for TLS 1.3 + H2 support..."
    echo ""

    local candidates=(
        "www.google.com"
        "dl.google.com"
        "www.microsoft.com"
        "update.microsoft.com"
        "www.apple.com"
        "www.samsung.com"
        "www.mozilla.org"
        "speed.cloudflare.com"
        "www.amd.com"
        "www.nvidia.com"
        "www.asus.com"
        "www.logitech.com"
        "www.dell.com"
        "www.lenovo.com"
        "www.cisco.com"
    )

    local good=0 partial=0 bad=0

    for sni in "${candidates[@]}"; do
        local result
        result=$(echo | timeout 8 openssl s_client -connect "$sni:443" -tls1_3 -alpn h2 2>/dev/null || true)

        local tls13 h2
        tls13=$(echo "$result" | grep -c "TLSv1.3" || true)
        h2=$(echo "$result" | grep -c "h2" || true)

        if [[ $tls13 -gt 0 && $h2 -gt 0 ]]; then
            echo -e "  ${GREEN}OK${NC}   $sni  (TLS 1.3 + H2)"
            ((good++)) || true
        elif [[ $tls13 -gt 0 ]]; then
            echo -e "  ${YELLOW}FAIR${NC} $sni  (TLS 1.3 only)"
            ((partial++)) || true
        else
            echo -e "  ${RED}FAIL${NC} $sni  (no TLS 1.3)"
            ((bad++)) || true
        fi
    done

    echo ""
    info "Results: $good ideal, $partial acceptable, $bad unsuitable"
    info "Use any 'OK' domain as your --sni target"
}

# ── Uninstall ──────────────────────────────────────────────────────────────
uninstall() {
    header "Uninstalling Xray Tunnel"

    read -rp "$(echo -e "${RED}This will remove all tunnel configs and services. Continue? [y/N]: ${NC}")" confirm
    [[ "${confirm,,}" != "y" ]] && { info "Cancelled."; exit 0; }

    log "Stopping services..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    systemctl stop xray-tunnel-health.timer 2>/dev/null || true
    systemctl disable xray-tunnel-health.timer 2>/dev/null || true

    log "Removing service files..."
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    rm -f "/etc/systemd/system/xray-tunnel-health.service"
    rm -f "/etc/systemd/system/xray-tunnel-health.timer"
    rm -f "$HEALTH_SCRIPT"
    rm -f /etc/logrotate.d/xray-tunnel

    log "Removing configs and logs..."
    rm -rf "$CONFIG_DIR"
    rm -rf "$LOG_DIR"

    log "Flushing iptables NAT rules..."
    iptables -t nat -F PREROUTING 2>/dev/null || true

    systemctl daemon-reload

    log "Uninstall complete"
    info "Xray binary left at $XRAY_BIN (may be used by x-ui)"
    info "To fully remove Xray: bash -c \"\$(curl -sL $XRAY_INSTALL_URL)\" @ remove"
}

# ── Change Fragment Settings (live) ────────────────────────────────────────
change_fragment() {
    header "Change TLS Fragment Settings"

    if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
        error "No config found. Run setup first."
        exit 1
    fi

    if ! grep -q "fragment" "$CONFIG_DIR/config.json" 2>/dev/null; then
        error "This is a gateway config (no fragment settings). Run on Iran relay."
        exit 1
    fi

    echo "Current fragment settings:"
    grep -A3 '"fragment"' "$CONFIG_DIR/config.json"
    echo ""

    echo "  1) Aggressive  - length=10-100,  interval=10-30ms"
    echo "  2) Normal       - length=100-200, interval=10-20ms"
    echo "  3) Ultra        - length=1-50,    interval=20-50ms"
    echo "  4) Micro        - length=1-20,    interval=30-50ms (extreme)"
    echo "  5) Custom"
    echo ""
    read -rp "$(echo -e "${CYAN}Choose mode: ${NC}")" mode

    local new_len new_int
    case ${mode:-1} in
        1) new_len="10-100";  new_int="10-30" ;;
        2) new_len="100-200"; new_int="10-20" ;;
        3) new_len="1-50";    new_int="20-50" ;;
        4) new_len="1-20";    new_int="30-50" ;;
        5)
            read -rp "  Length (e.g. 10-100): " new_len
            read -rp "  Interval ms (e.g. 10-30): " new_int
            ;;
        *) error "Invalid choice"; exit 1 ;;
    esac

    # Update config using sed (in-place JSON update)
    sed -i "s/\"length\": \"[^\"]*\"/\"length\": \"$new_len\"/" "$CONFIG_DIR/config.json"
    sed -i "s/\"interval\": \"[^\"]*\"/\"interval\": \"$new_int\"/" "$CONFIG_DIR/config.json"

    log "Fragment updated: length=$new_len, interval=${new_int}ms"

    # Validate and restart
    if "$XRAY_BIN" run -test -config "$CONFIG_DIR/config.json" 2>/dev/null; then
        systemctl restart "$SERVICE_NAME"
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log "Service restarted with new fragment settings"
        else
            error "Service failed to restart!"
        fi
    else
        error "Config validation failed after update!"
    fi
}

# ── Change SNI (live) ─────────────────────────────────────────────────────
change_sni() {
    header "Change REALITY SNI Target"

    if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
        error "No config found. Run setup first."
        exit 1
    fi

    local current_sni
    current_sni=$(grep -o '"serverName": "[^"]*"' "$CONFIG_DIR/config.json" | head -1 | cut -d'"' -f4)
    info "Current SNI: $current_sni"
    echo ""

    echo "  1) www.google.com"
    echo "  2) dl.google.com"
    echo "  3) www.microsoft.com"
    echo "  4) www.samsung.com"
    echo "  5) speed.cloudflare.com"
    echo "  6) Custom"
    echo ""
    read -rp "$(echo -e "${CYAN}New SNI: ${NC}")" choice

    local new_sni
    case ${choice:-1} in
        1) new_sni="www.google.com" ;;
        2) new_sni="dl.google.com" ;;
        3) new_sni="www.microsoft.com" ;;
        4) new_sni="www.samsung.com" ;;
        5) new_sni="speed.cloudflare.com" ;;
        6) read -rp "Enter domain: " new_sni ;;
        *) error "Invalid choice"; exit 1 ;;
    esac

    validate_sni "$new_sni" || {
        warn "SNI validation failed. Proceed anyway? [y/N]"
        read -rp "" yn
        [[ "${yn,,}" != "y" ]] && exit 1
    }

    # Update all SNI references in config
    sed -i "s/\"serverName\": \"[^\"]*\"/\"serverName\": \"$new_sni\"/g" "$CONFIG_DIR/config.json"
    sed -i "s|\"dest\": \"[^\"]*:443\"|\"dest\": \"$new_sni:443\"|g" "$CONFIG_DIR/config.json"

    # Update serverNames array
    sed -i "s/\"$current_sni\"/\"$new_sni\"/g" "$CONFIG_DIR/config.json"

    log "SNI updated: $current_sni -> $new_sni"

    if "$XRAY_BIN" run -test -config "$CONFIG_DIR/config.json" 2>/dev/null; then
        systemctl restart "$SERVICE_NAME"
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log "Service restarted with new SNI"
        else
            error "Service failed to restart!"
        fi
    else
        error "Config validation failed!"
    fi
}

# ══════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════
usage() {
    echo -e "${BOLD}Xray REALITY Tunnel - Advanced DPI Evasion for Iran${NC}"
    echo ""
    echo "Usage: bash $0 <command> [options]"
    echo ""
    echo -e "${BOLD}Setup Commands:${NC}"
    echo "  gateway          Setup Kharej server (run first)"
    echo "  relay            Setup Iran server (run second, needs gateway info)"
    echo ""
    echo -e "${BOLD}Management Commands:${NC}"
    echo "  status           Show tunnel status"
    echo "  diagnose         Run full diagnostics"
    echo "  change-fragment  Change TLS fragment settings (live)"
    echo "  change-sni       Change REALITY SNI target (live)"
    echo "  scan-sni         Find best SNI targets"
    echo "  uninstall        Remove tunnel completely"
    echo ""
    echo -e "${BOLD}Relay Options (non-interactive):${NC}"
    echo "  --gw-ip IP       Gateway server IP"
    echo "  --gw-port PORT   Gateway tunnel port (default: 443)"
    echo "  --uuid UUID      VLESS UUID from gateway setup"
    echo "  --pubkey KEY     REALITY public key from gateway"
    echo "  --shortid SID    REALITY short ID from gateway"
    echo "  --sni DOMAIN     SNI target (default: www.google.com)"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  bash $0 gateway"
    echo "  bash $0 relay --gw-ip 1.2.3.4 --gw-port 443 --uuid xxx --pubkey xxx --shortid xxx"
    echo "  bash $0 diagnose"
    echo "  bash $0 change-fragment"
}

# Parse command
COMMAND="${1:-}"
shift 2>/dev/null || true

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --gw-ip)     GW_IP="$2"; shift 2 ;;
        --gw-port)   GW_PORT="$2"; shift 2 ;;
        --uuid)      GW_UUID="$2"; shift 2 ;;
        --pubkey)    GW_PUBKEY="$2"; shift 2 ;;
        --shortid)   GW_SHORTID="$2"; shift 2 ;;
        --sni)       GW_SNI="$2"; shift 2 ;;
        *)           shift ;;
    esac
done

case "$COMMAND" in
    gateway|gw|kharej)
        setup_gateway
        ;;
    relay|ir|iran)
        setup_relay
        ;;
    status|st)
        show_status
        ;;
    diagnose|diag)
        diagnose
        ;;
    change-fragment|fragment|frag)
        change_fragment
        ;;
    change-sni|sni)
        change_sni
        ;;
    scan-sni|scan)
        scan_sni
        ;;
    uninstall|remove)
        uninstall
        ;;
    *)
        usage
        ;;
esac
