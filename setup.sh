#!/bin/bash

# ============================================================
# TCP Tunnel Setup Script (SSH TUN + stunnel TLS)
# Creates an encrypted TCP tunnel: SSH wrapped inside TLS
# Bypasses DPI that blocks SSH protocol detection
# Iran acts as relay: forwards ALL ports to Kharej
# ============================================================
# Usage:
#   Local:  bash setup.sh
#   Remote: bash <(curl -Ls https://raw.githubusercontent.com/kazemim99/gre-tunnel-setup/main/setup.sh)
# ============================================================
#
# Architecture:
#   Iran SSH -> stunnel (TLS) -> Kharej stunnel -> Kharej sshd
#   ISP sees normal HTTPS traffic, cannot detect SSH inside
#
# ============================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Constants
TUNNEL_CONF="/etc/ssh-tunnel.conf"
TUNNEL_SCRIPT="/usr/local/bin/ssh-tunnel.sh"
TUNNEL_SERVICE="ssh-tunnel"
STUNNEL_SERVICE="stunnel4"
SSH_KEY="/root/.ssh/tunnel_key"
TUN_NUM=0
TUN_DEV="tun${TUN_NUM}"
SERVER_TUN_IP="10.10.0.1"
CLIENT_TUN_IP="10.10.0.2"
TUN_SUBNET="30"
LOCAL_STUNNEL_PORT=2222

clear
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}   TCP Tunnel (SSH + stunnel TLS)${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "${CYAN}  SSH wrapped in TLS - bypasses DPI${NC}"
echo -e "${CYAN}  Iran relays ALL ports to Kharej${NC}"
echo -e "${BLUE}================================================${NC}"
echo
echo "Select server type:"
echo "  1. Iran Server (Relay/Client)"
echo "  2. Kharej Server (Foreign/Gateway)"
echo "  3. Manage Tunnel (Start/Stop/Status)"
echo "  4. Uninstall"
echo "  5. Cancel"
echo
read -p "Enter your choice (1-5): " SERVER_TYPE

case $SERVER_TYPE in
    1) MODE="iran" ;;
    2) MODE="kharej" ;;
    3) MODE="manage" ;;
    4) MODE="uninstall" ;;
    5) echo "Cancelled"; exit 0 ;;
    *) echo -e "${RED}Invalid choice${NC}"; exit 1 ;;
esac

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# ========================
# MANAGE TUNNEL
# ========================
if [ "$MODE" == "manage" ]; then
    echo
    echo "  1. Start tunnel (stunnel + ssh-tunnel)"
    echo "  2. Stop tunnel"
    echo "  3. Tunnel status"
    echo "  4. View logs (last 50 lines)"
    echo "  5. Restart tunnel"
    echo
    read -p "Choice: " MGMT

    case $MGMT in
        1)
            systemctl start $STUNNEL_SERVICE 2>/dev/null
            systemctl start $TUNNEL_SERVICE 2>/dev/null && echo -e "${GREEN}Started${NC}"
            ;;
        2)
            systemctl stop $TUNNEL_SERVICE 2>/dev/null
            echo -e "${GREEN}Stopped${NC}"
            ;;
        3)
            echo
            echo -e "${YELLOW}--- stunnel Status ---${NC}"
            systemctl status $STUNNEL_SERVICE --no-pager 2>/dev/null || echo "stunnel not running"
            echo
            echo -e "${YELLOW}--- SSH Tunnel Status ---${NC}"
            systemctl status $TUNNEL_SERVICE --no-pager 2>/dev/null || echo "SSH tunnel not running"
            echo
            echo -e "${YELLOW}--- Tunnel Device ---${NC}"
            ip addr show $TUN_DEV 2>/dev/null || echo "tun device not active"
            echo
            echo -e "${YELLOW}--- Port Forwarding (DNAT) ---${NC}"
            iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null | head -20
            echo
            echo -e "${YELLOW}--- Route Table ---${NC}"
            ip route show 2>/dev/null | head -10
            ;;
        4) journalctl -u $TUNNEL_SERVICE -n 50 --no-pager ;;
        5)
            systemctl restart $STUNNEL_SERVICE 2>/dev/null
            systemctl restart $TUNNEL_SERVICE 2>/dev/null && echo -e "${GREEN}Restarted${NC}"
            ;;
        *) echo "Invalid"; exit 1 ;;
    esac
    exit 0
fi

# ========================
# UNINSTALL
# ========================
if [ "$MODE" == "uninstall" ]; then
    echo
    echo -e "${YELLOW}Removing tunnel...${NC}"

    # Stop and disable services
    systemctl stop $TUNNEL_SERVICE 2>/dev/null
    systemctl disable $TUNNEL_SERVICE 2>/dev/null
    rm -f /etc/systemd/system/${TUNNEL_SERVICE}.service

    systemctl stop $STUNNEL_SERVICE 2>/dev/null
    systemctl disable $STUNNEL_SERVICE 2>/dev/null

    systemctl daemon-reload

    # Remove port forwarding rules
    if [ -f "$TUNNEL_CONF" ]; then
        source $TUNNEL_CONF
        LOCAL_IP_CONF=${LOCAL_IP:-""}
        if [ -n "$LOCAL_IP_CONF" ]; then
            iptables -t nat -D PREROUTING -p tcp -d $LOCAL_IP_CONF ! --dport 22 -j DNAT --to-destination $SERVER_TUN_IP 2>/dev/null
            iptables -t nat -D PREROUTING -p udp -d $LOCAL_IP_CONF -j DNAT --to-destination $SERVER_TUN_IP 2>/dev/null
        fi
        iptables -t nat -D POSTROUTING -o $TUN_DEV -j MASQUERADE 2>/dev/null
        iptables -D FORWARD -o $TUN_DEV -j ACCEPT 2>/dev/null
        iptables -D FORWARD -i $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    fi

    # Remove scripts and config
    rm -f $TUNNEL_SCRIPT
    rm -f $TUNNEL_CONF
    rm -f /etc/stunnel/ssh-tunnel.conf

    # Restore default route
    if [ -f /tmp/.tunnel_gateway ]; then
        SAVED_GW=$(cat /tmp/.tunnel_gateway)
        ip route replace default via $SAVED_GW 2>/dev/null
        rm -f /tmp/.tunnel_gateway
        rm -f /tmp/.tunnel_interface
    fi

    # Clean up tun device
    ip link set $TUN_DEV down 2>/dev/null

    echo -e "${GREEN}Uninstalled successfully${NC}"
    echo
    echo "Note: SSH key at $SSH_KEY was preserved."
    echo "Note: stunnel4 package was preserved (apt remove stunnel4 to remove)."
    exit 0
fi

# Auto-detect local IP
LOCAL_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
if [ -z "$LOCAL_IP" ]; then
    echo -e "${RED}Could not auto-detect local IP${NC}"
    read -p "Enter local IP manually: " LOCAL_IP
    if [ -z "$LOCAL_IP" ]; then
        echo -e "${RED}IP required. Exiting.${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}Detected Local IP: $LOCAL_IP${NC}"
echo

# ============================================================
# KHAREJ (GATEWAY) SERVER SETUP
# ============================================================
if [ "$MODE" == "kharej" ]; then
    echo -e "${YELLOW}=== Kharej (Gateway) Server Setup ===${NC}"
    echo

    read -p "stunnel TLS port (default 443, recommended): " STUNNEL_PORT
    STUNNEL_PORT=${STUNNEL_PORT:-443}

    echo
    echo -e "${YELLOW}=== Configuration Summary ===${NC}"
    echo "  Server Type:    Kharej (Gateway)"
    echo "  Local IP:       $LOCAL_IP"
    echo "  stunnel port:   $STUNNEL_PORT (TLS - visible to ISP as HTTPS)"
    echo "  SSH port:       22 (localhost only for tunnel)"
    echo "  Tunnel IP:      $SERVER_TUN_IP/$TUN_SUBNET"
    echo "  Client IP:      $CLIENT_TUN_IP"
    echo
    echo -e "${CYAN}  ISP sees: HTTPS traffic on port $STUNNEL_PORT${NC}"
    echo -e "${CYAN}  Reality:  SSH inside TLS inside port $STUNNEL_PORT${NC}"
    echo
    read -p "Proceed with setup? (y/n): " CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo "Cancelled"
        exit 0
    fi

    echo

    # --- Step 1: Install stunnel ---
    echo -e "${YELLOW}[1/6] Installing stunnel...${NC}"

    if ! command -v stunnel &>/dev/null; then
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq stunnel4
        elif command -v yum &>/dev/null; then
            yum install -y stunnel
        else
            echo -e "${RED}Cannot install stunnel. Install manually: apt install stunnel4${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}  ✓ stunnel installed${NC}"

    # --- Step 2: Generate TLS certificate ---
    echo -e "${YELLOW}[2/6] Generating TLS certificate...${NC}"

    CERT_DIR="/etc/stunnel"
    CERT_FILE="$CERT_DIR/stunnel.pem"
    mkdir -p $CERT_DIR

    if [ ! -f "$CERT_FILE" ]; then
        openssl req -new -x509 -days 3650 -nodes \
            -out $CERT_FILE -keyout $CERT_FILE \
            -subj "/C=US/O=Cloudflare/CN=cloudflare-dns.com" 2>/dev/null
        chmod 600 $CERT_FILE
        echo -e "${GREEN}  ✓ TLS certificate generated${NC}"
    else
        echo -e "${GREEN}  ✓ TLS certificate already exists${NC}"
    fi

    # --- Step 3: Configure stunnel ---
    echo -e "${YELLOW}[3/6] Configuring stunnel...${NC}"

    cat > /etc/stunnel/ssh-tunnel.conf << STEOF
; stunnel config for SSH tunnel
pid = /var/run/stunnel-ssh.pid

[ssh-tunnel]
accept = 0.0.0.0:${STUNNEL_PORT}
connect = 127.0.0.1:22
cert = ${CERT_FILE}
STEOF

    # Make sure stunnel is enabled
    if [ -f /etc/default/stunnel4 ]; then
        sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
    fi

    # Remove SSH from port 443 if it was added (stunnel uses 443 now)
    SSHD_CONF="/etc/ssh/sshd_config"
    if grep -q "^Port $STUNNEL_PORT" $SSHD_CONF 2>/dev/null; then
        sed -i "/^Port $STUNNEL_PORT/d" $SSHD_CONF
        # Make sure port 22 is there
        if ! grep -q "^Port " $SSHD_CONF; then
            echo "Port 22" >> $SSHD_CONF
        fi
        systemctl restart sshd
    fi

    echo -e "${GREEN}  ✓ stunnel configured (port $STUNNEL_PORT -> localhost:22)${NC}"

    # --- Step 4: Configure SSHD ---
    echo -e "${YELLOW}[4/6] Configuring SSH server...${NC}"

    # Backup
    cp $SSHD_CONF ${SSHD_CONF}.bak.$(date +%s) 2>/dev/null

    # PermitTunnel
    if grep -q "^#\?PermitTunnel" $SSHD_CONF; then
        sed -i 's/^#\?PermitTunnel.*/PermitTunnel point-to-point/' $SSHD_CONF
    else
        echo "PermitTunnel point-to-point" >> $SSHD_CONF
    fi

    # PermitRootLogin
    if grep -q "^#\?PermitRootLogin" $SSHD_CONF; then
        sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' $SSHD_CONF
    else
        echo "PermitRootLogin prohibit-password" >> $SSHD_CONF
    fi

    systemctl restart sshd
    echo -e "${GREEN}  ✓ SSH configured (PermitTunnel=point-to-point)${NC}"

    # --- Step 5: IP forwarding + iptables ---
    echo -e "${YELLOW}[5/6] Configuring IP forwarding and firewall...${NC}"

    # IP forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    # Detect main interface
    MAIN_IF=$(ip route | grep default | awk '{print $5; exit}')
    if [ -z "$MAIN_IF" ]; then
        read -p "  Enter main interface (e.g., eth0): " MAIN_IF
        [ -z "$MAIN_IF" ] && { echo -e "${RED}Required${NC}"; exit 1; }
    fi

    # NAT for tunnel traffic
    if ! iptables -t nat -C POSTROUTING -s 10.10.0.0/${TUN_SUBNET} -o $MAIN_IF -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s 10.10.0.0/${TUN_SUBNET} -o $MAIN_IF -j MASQUERADE
    fi

    # Allow forwarding
    if ! iptables -C FORWARD -i $TUN_DEV -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i $TUN_DEV -j ACCEPT
    fi
    if ! iptables -C FORWARD -o $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -o $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT
    fi

    # Allow stunnel port
    if ! iptables -C INPUT -p tcp --dport $STUNNEL_PORT -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p tcp --dport $STUNNEL_PORT -j ACCEPT
    fi

    echo -e "${GREEN}  ✓ IP forwarding + firewall configured${NC}"

    # --- Step 6: Start stunnel + persist ---
    echo -e "${YELLOW}[6/6] Starting stunnel and saving rules...${NC}"

    systemctl restart $STUNNEL_SERVICE 2>/dev/null || systemctl start $STUNNEL_SERVICE 2>/dev/null
    systemctl enable $STUNNEL_SERVICE 2>/dev/null

    # Save iptables
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null
    elif command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables.rules
        mkdir -p /etc/network/if-pre-up.d
        cat > /etc/network/if-pre-up.d/iptables << 'IPTEOF'
#!/bin/bash
iptables-restore < /etc/iptables.rules
IPTEOF
        chmod +x /etc/network/if-pre-up.d/iptables
    fi

    # Verify stunnel is listening
    sleep 2
    if ss -tlnp | grep -q ":${STUNNEL_PORT}"; then
        echo -e "${GREEN}  ✓ stunnel listening on port $STUNNEL_PORT${NC}"
    else
        echo -e "${RED}  ✗ stunnel not listening. Check: journalctl -u stunnel4${NC}"
    fi

    # Done
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     Kharej (Gateway) setup complete!                  ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${BLUE}Server Info:${NC}"
    echo "  IP:             $LOCAL_IP"
    echo "  stunnel port:   $STUNNEL_PORT (TLS)"
    echo "  SSH port:       22 (local only, behind stunnel)"
    echo "  Tunnel IP:      $SERVER_TUN_IP/$TUN_SUBNET"
    echo
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Run this script on the Iran server (choose option 1)"
    echo "  2. When asked, enter this server's IP: $LOCAL_IP"
    echo "  3. When asked, enter stunnel port: $STUNNEL_PORT"
    echo
    exit 0
fi

# ============================================================
# IRAN (RELAY/CLIENT) SERVER SETUP
# ============================================================
if [ "$MODE" == "iran" ]; then
    echo -e "${YELLOW}=== Iran (Relay/Client) Server Setup ===${NC}"
    echo
    echo -e "${CYAN}  SSH tunnel wrapped in TLS (stunnel)${NC}"
    echo -e "${CYAN}  ISP sees HTTPS, not SSH${NC}"
    echo

    read -p "Enter Kharej server IP: " REMOTE_IP
    if [ -z "$REMOTE_IP" ]; then
        echo -e "${RED}Remote IP cannot be empty. Exiting.${NC}"
        exit 1
    fi

    read -p "Enter Kharej stunnel port (default 443): " STUNNEL_PORT
    STUNNEL_PORT=${STUNNEL_PORT:-443}

    echo
    echo -e "${YELLOW}=== Configuration Summary ===${NC}"
    echo "  Server Type:     Iran (Relay)"
    echo "  Mode:            Forward ALL ports to Kharej"
    echo "  Local IP:        $LOCAL_IP"
    echo "  Kharej IP:       $REMOTE_IP"
    echo "  stunnel port:    $STUNNEL_PORT (TLS)"
    echo "  Local SSH port:  $LOCAL_STUNNEL_PORT (through stunnel)"
    echo "  Tunnel IP:       $CLIENT_TUN_IP/$TUN_SUBNET"
    echo
    echo -e "${CYAN}  Traffic: SSH -> stunnel TLS -> Kharej${NC}"
    echo -e "${CYAN}  ISP sees: HTTPS on port $STUNNEL_PORT${NC}"
    echo
    echo -e "${YELLOW}  Port 22 (SSH) will NOT be forwarded (management access)${NC}"
    echo
    read -p "Proceed with setup? (y/n): " CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo "Cancelled"
        exit 0
    fi

    echo

    # --- Step 1: Install stunnel ---
    echo -e "${YELLOW}[1/9] Installing stunnel...${NC}"

    if ! command -v stunnel &>/dev/null; then
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq stunnel4
        elif command -v yum &>/dev/null; then
            yum install -y stunnel
        else
            echo -e "${RED}Cannot install stunnel. Install manually: apt install stunnel4${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}  ✓ stunnel installed${NC}"

    # --- Step 2: Configure stunnel client ---
    echo -e "${YELLOW}[2/9] Configuring stunnel client...${NC}"

    mkdir -p /etc/stunnel

    cat > /etc/stunnel/ssh-tunnel.conf << STEOF
; stunnel client config for SSH tunnel
pid = /var/run/stunnel-ssh.pid
client = yes

[ssh-tunnel]
accept = 127.0.0.1:${LOCAL_STUNNEL_PORT}
connect = ${REMOTE_IP}:${STUNNEL_PORT}
STEOF

    # Enable stunnel
    if [ -f /etc/default/stunnel4 ]; then
        sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
    fi

    # Start stunnel
    systemctl restart $STUNNEL_SERVICE 2>/dev/null || systemctl start $STUNNEL_SERVICE 2>/dev/null
    systemctl enable $STUNNEL_SERVICE 2>/dev/null

    sleep 2
    if ss -tlnp | grep -q ":${LOCAL_STUNNEL_PORT}"; then
        echo -e "${GREEN}  ✓ stunnel listening on localhost:$LOCAL_STUNNEL_PORT${NC}"
    else
        echo -e "${RED}  ✗ stunnel not listening. Check: journalctl -u stunnel4${NC}"
        exit 1
    fi

    # --- Step 3: Generate SSH Key ---
    echo -e "${YELLOW}[3/9] Setting up SSH key...${NC}"

    if [ ! -f "$SSH_KEY" ]; then
        ssh-keygen -t ed25519 -f $SSH_KEY -N "" -C "tunnel-key" > /dev/null 2>&1
        echo -e "${GREEN}  ✓ SSH key generated${NC}"
    else
        echo -e "${GREEN}  ✓ SSH key already exists${NC}"
    fi

    # --- Step 4: Display key ---
    echo
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  IMPORTANT: Add this public key to Kharej server            ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}$(cat ${SSH_KEY}.pub)${NC}"
    echo
    echo "Run this command on the Kharej server:"
    echo -e "${GREEN}  mkdir -p /root/.ssh && echo '$(cat ${SSH_KEY}.pub)' >> /root/.ssh/authorized_keys${NC}"
    echo
    read -p "Press Enter after adding the key to Kharej server... "

    # --- Step 5: Test SSH through stunnel ---
    echo -e "${YELLOW}[4/9] Testing SSH through stunnel (TLS)...${NC}"

    SSH_TEST=$(ssh -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=15 \
        -o BatchMode=yes \
        -p $LOCAL_STUNNEL_PORT \
        -i $SSH_KEY \
        root@127.0.0.1 "echo SUCCESS" 2>&1)

    if echo "$SSH_TEST" | grep -q "SUCCESS"; then
        echo -e "${GREEN}  ✓ SSH through stunnel works!${NC}"
    else
        echo -e "${RED}  ✗ SSH through stunnel failed${NC}"
        echo
        echo -e "${YELLOW}Troubleshooting:${NC}"
        echo "  1. Check stunnel on Kharej: ss -tlnp | grep $STUNNEL_PORT"
        echo "  2. Check stunnel logs: journalctl -u stunnel4"
        echo "  3. Verify SSH key is in Kharej /root/.ssh/authorized_keys"
        echo "  4. Verify Kharej sshd has PermitTunnel and PermitRootLogin"
        echo "  5. Test stunnel connectivity: nc -zv $REMOTE_IP $STUNNEL_PORT"
        echo
        echo "  Output: $SSH_TEST"
        exit 1
    fi

    # --- Step 6: Verify PermitTunnel ---
    echo -e "${YELLOW}[5/9] Verifying Kharej tunnel support...${NC}"

    TUNNEL_CHECK=$(ssh -o BatchMode=yes -p $LOCAL_STUNNEL_PORT -i $SSH_KEY root@127.0.0.1 \
        "grep -c 'PermitTunnel point-to-point' /etc/ssh/sshd_config" 2>/dev/null)

    if [ "$TUNNEL_CHECK" -gt 0 ] 2>/dev/null; then
        echo -e "${GREEN}  ✓ PermitTunnel is enabled on Kharej${NC}"
    else
        echo -e "${RED}  ✗ PermitTunnel not configured on Kharej${NC}"
        echo "  Run this script on Kharej first (option 2)."
        exit 1
    fi

    # --- Step 7: Detect gateway ---
    echo -e "${YELLOW}[6/9] Detecting network gateway...${NC}"

    GATEWAY=$(ip route | grep default | awk '{print $3; exit}')
    MAIN_IF=$(ip route | grep default | awk '{print $5; exit}')

    if [ -z "$GATEWAY" ]; then
        read -p "  Enter gateway IP manually: " GATEWAY
        [ -z "$GATEWAY" ] && { echo -e "${RED}Gateway required${NC}"; exit 1; }
    fi
    [ -z "$MAIN_IF" ] && MAIN_IF="eth0"
    echo -e "${GREEN}  ✓ Gateway: $GATEWAY (via $MAIN_IF)${NC}"

    # --- Step 8: Port forwarding + IP forwarding ---
    echo -e "${YELLOW}[7/9] Configuring port forwarding (relay mode)...${NC}"

    # IP forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    echo -e "${GREEN}  ✓ IP forwarding enabled${NC}"

    # DNAT: Forward all TCP except port 22
    if ! iptables -t nat -C PREROUTING -p tcp -d $LOCAL_IP ! --dport 22 -j DNAT --to-destination $SERVER_TUN_IP 2>/dev/null; then
        iptables -t nat -A PREROUTING -p tcp -d $LOCAL_IP ! --dport 22 -j DNAT --to-destination $SERVER_TUN_IP
    fi
    echo -e "${GREEN}  ✓ TCP port forwarding: all -> Kharej (except 22)${NC}"

    # DNAT: Forward all UDP
    if ! iptables -t nat -C PREROUTING -p udp -d $LOCAL_IP -j DNAT --to-destination $SERVER_TUN_IP 2>/dev/null; then
        iptables -t nat -A PREROUTING -p udp -d $LOCAL_IP -j DNAT --to-destination $SERVER_TUN_IP
    fi
    echo -e "${GREEN}  ✓ UDP port forwarding: all -> Kharej${NC}"

    # MASQUERADE
    if ! iptables -t nat -C POSTROUTING -o $TUN_DEV -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -o $TUN_DEV -j MASQUERADE
    fi

    # FORWARD
    if ! iptables -C FORWARD -o $TUN_DEV -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -o $TUN_DEV -j ACCEPT
    fi
    if ! iptables -C FORWARD -i $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT
    fi
    echo -e "${GREEN}  ✓ NAT and forwarding rules configured${NC}"

    # Save iptables
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null
    elif command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables.rules
        mkdir -p /etc/network/if-pre-up.d
        cat > /etc/network/if-pre-up.d/iptables << 'IPTEOF'
#!/bin/bash
iptables-restore < /etc/iptables.rules
IPTEOF
        chmod +x /etc/network/if-pre-up.d/iptables
    fi
    echo -e "${GREEN}  ✓ Firewall rules saved${NC}"

    # --- Step 9: Create config + tunnel script + systemd ---
    echo -e "${YELLOW}[8/9] Creating tunnel configuration...${NC}"

    cat > $TUNNEL_CONF << CONFEOF
# SSH Tunnel Configuration (with stunnel)
# Generated on $(date)
REMOTE_IP=$REMOTE_IP
LOCAL_IP=$LOCAL_IP
STUNNEL_PORT=$STUNNEL_PORT
LOCAL_STUNNEL_PORT=$LOCAL_STUNNEL_PORT
SSH_KEY=$SSH_KEY
TUN_NUM=$TUN_NUM
SERVER_TUN_IP=$SERVER_TUN_IP
CLIENT_TUN_IP=$CLIENT_TUN_IP
TUN_SUBNET=$TUN_SUBNET
CONFEOF

    echo -e "${GREEN}  ✓ Config saved: $TUNNEL_CONF${NC}"

    echo -e "${YELLOW}[9/9] Creating tunnel script and service...${NC}"

    cat > $TUNNEL_SCRIPT << 'SCRIPTEOF'
#!/bin/bash
# SSH TUN Tunnel via stunnel (TLS)
# Managed by setup.sh

source /etc/ssh-tunnel.conf

TUN_DEV="tun${TUN_NUM}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }

cleanup() {
    log "Cleaning up..."
    if [ -n "$SSH_PID" ] && kill -0 $SSH_PID 2>/dev/null; then
        kill $SSH_PID 2>/dev/null
        wait $SSH_PID 2>/dev/null
    fi
    if [ -f /tmp/.tunnel_gateway ]; then
        SAVED_GW=$(cat /tmp/.tunnel_gateway)
        SAVED_IF=$(cat /tmp/.tunnel_interface 2>/dev/null || echo "eth0")
        ip route replace default via $SAVED_GW dev $SAVED_IF 2>/dev/null
        ip route del $REMOTE_IP via $SAVED_GW 2>/dev/null
    fi
    ip link set $TUN_DEV down 2>/dev/null
    log "Cleanup done"
}

trap cleanup EXIT INT TERM

# Make sure stunnel is running
if ! ss -tln | grep -q ":${LOCAL_STUNNEL_PORT} "; then
    log "stunnel not running, starting..."
    systemctl start stunnel4 2>/dev/null
    sleep 3
    if ! ss -tln | grep -q ":${LOCAL_STUNNEL_PORT} "; then
        log "ERROR: stunnel failed to start on port $LOCAL_STUNNEL_PORT"
        exit 1
    fi
fi
log "stunnel is running on localhost:$LOCAL_STUNNEL_PORT"

# Detect gateway
GATEWAY=$(ip route | grep default | grep -v "$TUN_DEV" | awk '{print $3; exit}')
MAIN_IF=$(ip route | grep default | grep -v "$TUN_DEV" | awk '{print $5; exit}')

if [ -z "$GATEWAY" ]; then
    if [ -f /tmp/.tunnel_gateway ]; then
        GATEWAY=$(cat /tmp/.tunnel_gateway)
        MAIN_IF=$(cat /tmp/.tunnel_interface 2>/dev/null || echo "eth0")
        log "Using saved gateway: $GATEWAY"
    else
        log "ERROR: Cannot detect gateway"
        exit 1
    fi
fi

echo "$GATEWAY" > /tmp/.tunnel_gateway
echo "$MAIN_IF" > /tmp/.tunnel_interface
log "Gateway: $GATEWAY via $MAIN_IF"

# Prevent routing loop
ip route replace $REMOTE_IP via $GATEWAY dev $MAIN_IF

# Clean up existing tun
ip link set $TUN_DEV down 2>/dev/null

# SSH through stunnel (connect to localhost, stunnel handles TLS to Kharej)
log "Connecting SSH tunnel via stunnel to $REMOTE_IP..."
ssh -w ${TUN_NUM}:${TUN_NUM} \
    -o Tunnel=point-to-point \
    -o ServerAliveInterval=15 \
    -o ServerAliveCountMax=3 \
    -o ExitOnForwardFailure=yes \
    -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=15 \
    -o BatchMode=yes \
    -o UserKnownHostsFile=/root/.ssh/tunnel_known_hosts \
    -p $LOCAL_STUNNEL_PORT \
    -i $SSH_KEY \
    root@127.0.0.1 \
    "ip addr replace ${SERVER_TUN_IP}/${TUN_SUBNET} dev tun${TUN_NUM} && ip link set tun${TUN_NUM} up && exec sleep infinity" &

SSH_PID=$!

# Wait for tun device
log "Waiting for tunnel device..."
TUN_READY=false
for i in $(seq 1 20); do
    if ip link show $TUN_DEV &>/dev/null; then
        TUN_READY=true
        break
    fi
    if ! kill -0 $SSH_PID 2>/dev/null; then
        log "ERROR: SSH process died"
        exit 1
    fi
    sleep 1
done

if [ "$TUN_READY" = false ]; then
    log "ERROR: Tunnel device $TUN_DEV did not appear after 20s"
    exit 1
fi

# Configure local tun
ip addr replace ${CLIENT_TUN_IP}/${TUN_SUBNET} dev $TUN_DEV
ip link set $TUN_DEV up
log "Tunnel device configured: $CLIENT_TUN_IP/$TUN_SUBNET"

# Re-apply port forwarding rules
log "Applying port forwarding rules..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1

if ! iptables -t nat -C PREROUTING -p tcp -d $LOCAL_IP ! --dport 22 -j DNAT --to-destination $SERVER_TUN_IP 2>/dev/null; then
    iptables -t nat -A PREROUTING -p tcp -d $LOCAL_IP ! --dport 22 -j DNAT --to-destination $SERVER_TUN_IP
fi
if ! iptables -t nat -C PREROUTING -p udp -d $LOCAL_IP -j DNAT --to-destination $SERVER_TUN_IP 2>/dev/null; then
    iptables -t nat -A PREROUTING -p udp -d $LOCAL_IP -j DNAT --to-destination $SERVER_TUN_IP
fi
if ! iptables -t nat -C POSTROUTING -o $TUN_DEV -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -o $TUN_DEV -j MASQUERADE
fi
if ! iptables -C FORWARD -o $TUN_DEV -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -o $TUN_DEV -j ACCEPT
fi
if ! iptables -C FORWARD -i $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -i $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT
fi
log "Port forwarding rules applied"

# Test connectivity
log "Testing tunnel..."
if ping -c 3 -W 3 $SERVER_TUN_IP > /dev/null 2>&1; then
    log "Tunnel is UP - Kharej reachable at $SERVER_TUN_IP"
else
    log "WARNING: Ping failed (TCP may still work)"
fi

log "========================================="
log "  Tunnel established - Relay mode active"
log "  Local:  $CLIENT_TUN_IP"
log "  Remote: $SERVER_TUN_IP"
log "  Via:    stunnel TLS on port $STUNNEL_PORT"
log "  All ports -> Kharej (except SSH 22)"
log "========================================="

# Wait for SSH (systemd restarts on exit)
wait $SSH_PID
EXIT_CODE=$?
log "SSH exited with code $EXIT_CODE"
exit $EXIT_CODE
SCRIPTEOF

    chmod +x $TUNNEL_SCRIPT

    # Create systemd service
    cat > /etc/systemd/system/${TUNNEL_SERVICE}.service << SVCEOF
[Unit]
Description=SSH TUN Tunnel via stunnel (Relay Mode)
After=network-online.target stunnel4.service
Wants=network-online.target
Requires=stunnel4.service

[Service]
Type=simple
ExecStart=$TUNNEL_SCRIPT
Restart=always
RestartSec=10
KillMode=mixed
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable $TUNNEL_SERVICE > /dev/null 2>&1
    echo -e "${GREEN}  ✓ Tunnel script and service created${NC}"

    # Start the tunnel
    echo
    echo -e "${YELLOW}Starting tunnel...${NC}"
    systemctl start $TUNNEL_SERVICE

    echo "Waiting for tunnel to establish..."
    sleep 10

    # Check status
    if systemctl is-active --quiet $TUNNEL_SERVICE; then
        if ip link show $TUN_DEV &>/dev/null; then
            echo -e "${GREEN}  ✓ Tunnel service is running${NC}"
            echo -e "${GREEN}  ✓ Tunnel device $TUN_DEV is up${NC}"

            if ping -c 2 -W 3 $SERVER_TUN_IP > /dev/null 2>&1; then
                echo -e "${GREEN}  ✓ Kharej reachable through tunnel${NC}"
            else
                echo -e "${YELLOW}  ⚠ Ping failed (TCP may still work)${NC}"
            fi
        else
            echo -e "${YELLOW}  ⚠ Tunnel device not yet active${NC}"
        fi
    else
        echo -e "${RED}  ✗ Tunnel service failed${NC}"
        echo "  Check: journalctl -u $TUNNEL_SERVICE -n 30 --no-pager"
    fi

    # Done
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     Iran (Relay) setup complete!                      ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${BLUE}Relay Info:${NC}"
    echo "  This server (Iran): $LOCAL_IP"
    echo "  Kharej tunnel IP:   $SERVER_TUN_IP"
    echo "  stunnel port:       $STUNNEL_PORT (TLS)"
    echo "  DPI bypass:         SSH wrapped in TLS"
    echo
    echo -e "${BLUE}Port Forwarding:${NC}"
    echo "  TCP:  ALL ports -> Kharej (except 22)"
    echo "  UDP:  ALL ports -> Kharej"
    echo
    echo -e "${YELLOW}V2Ray Configuration:${NC}"
    echo "  In your V2Ray client, use:"
    echo "    Address: $LOCAL_IP"
    echo "    Port:    (same port as V2Ray/Xray on Kharej)"
    echo "  Traffic relays to Kharej automatically."
    echo
    echo -e "${BLUE}Management Commands:${NC}"
    echo "  Status:   systemctl status $TUNNEL_SERVICE"
    echo "  Logs:     journalctl -u $TUNNEL_SERVICE -f"
    echo "  Stop:     systemctl stop $TUNNEL_SERVICE"
    echo "  Start:    systemctl start $TUNNEL_SERVICE"
    echo "  Restart:  systemctl restart $TUNNEL_SERVICE"
    echo
    exit 0
fi
