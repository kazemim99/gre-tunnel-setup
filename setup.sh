#!/bin/bash

# ============================================================
# TCP Tunnel Setup Script (SSH TUN Method)
# Creates an encrypted TCP-based VPN tunnel using SSH
# Iran acts as relay: forwards ALL ports to Kharej via tunnel
# Works where GRE/IPIP/6in4 tunnels are blocked
# ============================================================
# Usage:
#   Local:  bash setup.sh
#   Remote: bash <(curl -Ls https://raw.githubusercontent.com/kazemim99/gre-tunnel-setup/main/setup.sh)
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
SSH_KEY="/root/.ssh/tunnel_key"
TUN_NUM=0
TUN_DEV="tun${TUN_NUM}"
SERVER_TUN_IP="10.10.0.1"
CLIENT_TUN_IP="10.10.0.2"
TUN_SUBNET="30"

clear
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}   TCP Tunnel Setup (SSH TUN Method)${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "${CYAN}  Encrypted TCP tunnel over SSH${NC}"
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
    echo "  1. Start tunnel"
    echo "  2. Stop tunnel"
    echo "  3. Tunnel status"
    echo "  4. View logs (last 50 lines)"
    echo "  5. Restart tunnel"
    echo
    read -p "Choice: " MGMT

    case $MGMT in
        1) systemctl start $TUNNEL_SERVICE && echo -e "${GREEN}Started${NC}" ;;
        2) systemctl stop $TUNNEL_SERVICE && echo -e "${GREEN}Stopped${NC}" ;;
        3)
            echo
            systemctl status $TUNNEL_SERVICE --no-pager 2>/dev/null || echo "Service not found"
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
        5) systemctl restart $TUNNEL_SERVICE && echo -e "${GREEN}Restarted${NC}" ;;
        *) echo "Invalid"; exit 1 ;;
    esac
    exit 0
fi

# ========================
# UNINSTALL
# ========================
if [ "$MODE" == "uninstall" ]; then
    echo
    echo -e "${YELLOW}Removing SSH tunnel...${NC}"

    # Stop and disable service
    systemctl stop $TUNNEL_SERVICE 2>/dev/null
    systemctl disable $TUNNEL_SERVICE 2>/dev/null
    rm -f /etc/systemd/system/${TUNNEL_SERVICE}.service
    systemctl daemon-reload

    # Remove port forwarding rules
    if [ -f "$TUNNEL_CONF" ]; then
        source $TUNNEL_CONF
        # Remove DNAT rules
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

    # Restore default route from saved gateway
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
    echo "Note: sshd_config changes on Kharej were preserved."
    echo "Note: IP forwarding (sysctl) was preserved."
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

    # Ask for SSH port
    echo "Which port should SSH listen on for the tunnel?"
    echo "  - Port 443 is recommended (looks like HTTPS, rarely blocked)"
    echo "  - Port 22 is default SSH (may be filtered)"
    echo
    read -p "SSH tunnel port (default 443): " SSH_PORT
    SSH_PORT=${SSH_PORT:-443}

    echo
    echo -e "${YELLOW}=== Configuration Summary ===${NC}"
    echo "  Server Type:  Kharej (Gateway)"
    echo "  Local IP:     $LOCAL_IP"
    echo "  SSH Port:     $SSH_PORT"
    echo "  Tunnel IP:    $SERVER_TUN_IP/$TUN_SUBNET"
    echo "  Client IP:    $CLIENT_TUN_IP"
    echo
    echo -e "${CYAN}  V2Ray/Xray should be installed on this server.${NC}"
    echo -e "${CYAN}  All ports on Iran will be forwarded here via tunnel.${NC}"
    echo
    read -p "Proceed with setup? (y/n): " CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo "Cancelled"
        exit 0
    fi

    echo

    # --- Step 1: Configure SSHD ---
    echo -e "${YELLOW}[1/5] Configuring SSH server...${NC}"

    SSHD_CONF="/etc/ssh/sshd_config"

    # Backup
    cp $SSHD_CONF ${SSHD_CONF}.bak.$(date +%s)

    # PermitTunnel - required for SSH TUN
    if grep -q "^#\?PermitTunnel" $SSHD_CONF; then
        sed -i 's/^#\?PermitTunnel.*/PermitTunnel point-to-point/' $SSHD_CONF
    else
        echo "PermitTunnel point-to-point" >> $SSHD_CONF
    fi

    # PermitRootLogin with key only
    if grep -q "^#\?PermitRootLogin" $SSHD_CONF; then
        sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' $SSHD_CONF
    else
        echo "PermitRootLogin prohibit-password" >> $SSHD_CONF
    fi

    # Add tunnel SSH port (keep port 22 for safety)
    if [ "$SSH_PORT" != "22" ]; then
        if ! grep -q "^Port $SSH_PORT" $SSHD_CONF; then
            if ! grep -q "^Port " $SSHD_CONF; then
                echo "Port 22" >> $SSHD_CONF
            fi
            echo "Port $SSH_PORT" >> $SSHD_CONF
        fi
    fi

    # Restart SSH
    systemctl restart sshd
    echo -e "${GREEN}  ✓ SSH configured (PermitTunnel=point-to-point, Port $SSH_PORT)${NC}"

    # --- Step 2: IP Forwarding ---
    echo -e "${YELLOW}[2/5] Enabling IP forwarding...${NC}"

    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    echo -e "${GREEN}  ✓ IP forwarding enabled${NC}"

    # --- Step 3: Detect main interface ---
    echo -e "${YELLOW}[3/5] Detecting network interface...${NC}"

    MAIN_IF=$(ip route | grep default | awk '{print $5; exit}')
    if [ -z "$MAIN_IF" ]; then
        read -p "  Enter main interface manually (e.g., eth0): " MAIN_IF
        if [ -z "$MAIN_IF" ]; then
            echo -e "${RED}Interface required. Exiting.${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}  ✓ Interface: $MAIN_IF${NC}"

    # --- Step 4: Iptables rules ---
    echo -e "${YELLOW}[4/5] Configuring firewall rules...${NC}"

    # NAT masquerade for tunnel traffic going to internet
    if ! iptables -t nat -C POSTROUTING -s 10.10.0.0/${TUN_SUBNET} -o $MAIN_IF -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s 10.10.0.0/${TUN_SUBNET} -o $MAIN_IF -j MASQUERADE
    fi

    # Allow forwarding from/to tunnel
    if ! iptables -C FORWARD -i $TUN_DEV -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i $TUN_DEV -j ACCEPT
    fi
    if ! iptables -C FORWARD -o $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -o $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT
    fi

    # Allow SSH tunnel port
    if ! iptables -C INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT
    fi

    echo -e "${GREEN}  ✓ Firewall rules configured${NC}"

    # --- Step 5: Persist iptables ---
    echo -e "${YELLOW}[5/5] Saving firewall rules...${NC}"

    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null
        echo -e "${GREEN}  ✓ Rules saved (netfilter-persistent)${NC}"
    elif command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables.rules
        mkdir -p /etc/network/if-pre-up.d
        cat > /etc/network/if-pre-up.d/iptables << 'IPTEOF'
#!/bin/bash
iptables-restore < /etc/iptables.rules
IPTEOF
        chmod +x /etc/network/if-pre-up.d/iptables
        echo -e "${GREEN}  ✓ Rules saved (iptables-save)${NC}"
    else
        echo -e "${YELLOW}  ⚠ Could not auto-save. Install iptables-persistent:${NC}"
        echo "    apt install iptables-persistent"
    fi

    # Done
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     Kharej (Gateway) setup complete!                  ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${BLUE}Server Info:${NC}"
    echo "  IP:         $LOCAL_IP"
    echo "  SSH Port:   $SSH_PORT"
    echo "  Tunnel IP:  $SERVER_TUN_IP/$TUN_SUBNET"
    echo
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Install V2Ray/Xray on this server if not already installed"
    echo "  2. Run this script on the Iran server (choose option 1)"
    echo "  3. When asked, enter this server's IP: $LOCAL_IP"
    echo "  4. When asked, enter SSH port: $SSH_PORT"
    echo
    echo -e "${YELLOW}V2Ray note:${NC}"
    echo "  V2Ray/Xray should listen on 0.0.0.0 (all interfaces)"
    echo "  so it accepts traffic coming through the tunnel."
    echo
    exit 0
fi

# ============================================================
# IRAN (RELAY/CLIENT) SERVER SETUP
# ============================================================
if [ "$MODE" == "iran" ]; then
    echo -e "${YELLOW}=== Iran (Relay/Client) Server Setup ===${NC}"
    echo
    echo -e "${CYAN}  This server will relay ALL incoming traffic${NC}"
    echo -e "${CYAN}  to Kharej through an encrypted SSH tunnel.${NC}"
    echo -e "${CYAN}  Users connect to this IP, traffic exits via Kharej.${NC}"
    echo

    read -p "Enter Kharej server IP: " REMOTE_IP
    if [ -z "$REMOTE_IP" ]; then
        echo -e "${RED}Remote IP cannot be empty. Exiting.${NC}"
        exit 1
    fi

    read -p "Enter Kharej SSH port (default 443): " SSH_PORT
    SSH_PORT=${SSH_PORT:-443}

    echo
    echo -e "${YELLOW}=== Configuration Summary ===${NC}"
    echo "  Server Type:  Iran (Relay)"
    echo "  Mode:         Forward ALL ports to Kharej"
    echo "  Local IP:     $LOCAL_IP"
    echo "  Kharej IP:    $REMOTE_IP"
    echo "  SSH Port:     $SSH_PORT"
    echo "  Tunnel IP:    $CLIENT_TUN_IP/$TUN_SUBNET"
    echo "  Kharej TUN:   $SERVER_TUN_IP (via tunnel)"
    echo
    echo -e "${CYAN}  Traffic flow:${NC}"
    echo -e "${CYAN}  User -> $LOCAL_IP:PORT -> [tunnel] -> $SERVER_TUN_IP:PORT (Kharej V2Ray)${NC}"
    echo
    echo -e "${YELLOW}  Port 22 (SSH) will NOT be forwarded (management access)${NC}"
    echo
    read -p "Proceed with setup? (y/n): " CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo "Cancelled"
        exit 0
    fi

    echo

    # --- Step 1: Generate SSH Key ---
    echo -e "${YELLOW}[1/8] Setting up SSH key...${NC}"

    if [ ! -f "$SSH_KEY" ]; then
        ssh-keygen -t ed25519 -f $SSH_KEY -N "" -C "tunnel-key" > /dev/null 2>&1
        echo -e "${GREEN}  ✓ SSH key generated${NC}"
    else
        echo -e "${GREEN}  ✓ SSH key already exists${NC}"
    fi

    # --- Step 2: Display key for user to copy ---
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

    # --- Step 3: Test SSH connection ---
    echo -e "${YELLOW}[2/8] Testing SSH connection to Kharej...${NC}"

    SSH_TEST=$(ssh -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 \
        -o BatchMode=yes \
        -p $SSH_PORT \
        -i $SSH_KEY \
        root@$REMOTE_IP "echo SUCCESS" 2>&1)

    if echo "$SSH_TEST" | grep -q "SUCCESS"; then
        echo -e "${GREEN}  ✓ SSH connection successful${NC}"
    else
        echo -e "${RED}  ✗ Cannot connect to Kharej via SSH${NC}"
        echo
        echo -e "${YELLOW}Troubleshooting:${NC}"
        echo "  1. Verify the public key was added to Kharej /root/.ssh/authorized_keys"
        echo "  2. Check Kharej SSH is running: systemctl status sshd"
        echo "  3. Verify port $SSH_PORT is open on Kharej: ss -tlnp | grep $SSH_PORT"
        echo "  4. Test basic connectivity: ping $REMOTE_IP"
        echo "  5. Check Kharej has PermitTunnel and PermitRootLogin configured"
        echo
        echo "  SSH output: $SSH_TEST"
        exit 1
    fi

    # --- Step 4: Check PermitTunnel on remote ---
    echo -e "${YELLOW}[3/8] Verifying Kharej tunnel support...${NC}"

    TUNNEL_CHECK=$(ssh -o BatchMode=yes -p $SSH_PORT -i $SSH_KEY root@$REMOTE_IP \
        "grep -c 'PermitTunnel point-to-point' /etc/ssh/sshd_config" 2>/dev/null)

    if [ "$TUNNEL_CHECK" -gt 0 ] 2>/dev/null; then
        echo -e "${GREEN}  ✓ PermitTunnel is enabled on Kharej${NC}"
    else
        echo -e "${RED}  ✗ PermitTunnel not configured on Kharej${NC}"
        echo "  Run this script on Kharej first (option 2) to configure it."
        exit 1
    fi

    # --- Step 5: Detect gateway ---
    echo -e "${YELLOW}[4/8] Detecting network gateway...${NC}"

    GATEWAY=$(ip route | grep default | awk '{print $3; exit}')
    MAIN_IF=$(ip route | grep default | awk '{print $5; exit}')

    if [ -z "$GATEWAY" ]; then
        read -p "  Enter gateway IP manually: " GATEWAY
        if [ -z "$GATEWAY" ]; then
            echo -e "${RED}Gateway required. Exiting.${NC}"
            exit 1
        fi
    fi
    if [ -z "$MAIN_IF" ]; then
        MAIN_IF="eth0"
    fi
    echo -e "${GREEN}  ✓ Gateway: $GATEWAY (via $MAIN_IF)${NC}"

    # --- Step 6: Enable IP forwarding + port forwarding ---
    echo -e "${YELLOW}[5/8] Configuring port forwarding (relay mode)...${NC}"

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    echo -e "${GREEN}  ✓ IP forwarding enabled${NC}"

    # DNAT: Forward all incoming TCP to Kharej (except port 22 for SSH management)
    if ! iptables -t nat -C PREROUTING -p tcp -d $LOCAL_IP ! --dport 22 -j DNAT --to-destination $SERVER_TUN_IP 2>/dev/null; then
        iptables -t nat -A PREROUTING -p tcp -d $LOCAL_IP ! --dport 22 -j DNAT --to-destination $SERVER_TUN_IP
    fi
    echo -e "${GREEN}  ✓ TCP port forwarding: all ports -> Kharej (except 22)${NC}"

    # DNAT: Forward all incoming UDP to Kharej
    if ! iptables -t nat -C PREROUTING -p udp -d $LOCAL_IP -j DNAT --to-destination $SERVER_TUN_IP 2>/dev/null; then
        iptables -t nat -A PREROUTING -p udp -d $LOCAL_IP -j DNAT --to-destination $SERVER_TUN_IP
    fi
    echo -e "${GREEN}  ✓ UDP port forwarding: all ports -> Kharej${NC}"

    # MASQUERADE traffic going through tunnel (so Kharej sends replies back through tunnel)
    if ! iptables -t nat -C POSTROUTING -o $TUN_DEV -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -o $TUN_DEV -j MASQUERADE
    fi

    # Allow forwarding between main interface and tunnel
    if ! iptables -C FORWARD -o $TUN_DEV -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -o $TUN_DEV -j ACCEPT
    fi
    if ! iptables -C FORWARD -i $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT
    fi
    echo -e "${GREEN}  ✓ NAT masquerade and forwarding rules configured${NC}"

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

    # --- Step 7: Create config and tunnel script ---
    echo -e "${YELLOW}[6/8] Creating tunnel configuration...${NC}"

    cat > $TUNNEL_CONF << CONFEOF
# SSH Tunnel Configuration
# Generated on $(date)
REMOTE_IP=$REMOTE_IP
LOCAL_IP=$LOCAL_IP
SSH_PORT=$SSH_PORT
SSH_KEY=$SSH_KEY
TUN_NUM=$TUN_NUM
SERVER_TUN_IP=$SERVER_TUN_IP
CLIENT_TUN_IP=$CLIENT_TUN_IP
TUN_SUBNET=$TUN_SUBNET
CONFEOF

    echo -e "${GREEN}  ✓ Config saved: $TUNNEL_CONF${NC}"

    echo -e "${YELLOW}[7/8] Creating tunnel connection script...${NC}"

    cat > $TUNNEL_SCRIPT << 'SCRIPTEOF'
#!/bin/bash
# SSH TUN Tunnel Connection Script (Relay Mode)
# Managed by setup.sh - do not edit manually

source /etc/ssh-tunnel.conf

TUN_DEV="tun${TUN_NUM}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }

cleanup() {
    log "Cleaning up..."
    # Kill SSH tunnel process
    if [ -n "$SSH_PID" ] && kill -0 $SSH_PID 2>/dev/null; then
        kill $SSH_PID 2>/dev/null
        wait $SSH_PID 2>/dev/null
    fi
    # Restore default route
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

# Detect real gateway BEFORE any route changes
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

# Save gateway for cleanup and future restarts
echo "$GATEWAY" > /tmp/.tunnel_gateway
echo "$MAIN_IF" > /tmp/.tunnel_interface
log "Gateway: $GATEWAY via $MAIN_IF"

# Prevent routing loop: route to Kharej via real gateway
ip route replace $REMOTE_IP via $GATEWAY dev $MAIN_IF

# Clean up any existing tun device
ip link set $TUN_DEV down 2>/dev/null

# Start SSH tunnel
log "Connecting SSH tunnel to $REMOTE_IP:$SSH_PORT..."
ssh -w ${TUN_NUM}:${TUN_NUM} \
    -o Tunnel=point-to-point \
    -o ServerAliveInterval=15 \
    -o ServerAliveCountMax=3 \
    -o ExitOnForwardFailure=yes \
    -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=15 \
    -o BatchMode=yes \
    -p $SSH_PORT \
    -i $SSH_KEY \
    root@$REMOTE_IP \
    "ip addr replace ${SERVER_TUN_IP}/${TUN_SUBNET} dev tun${TUN_NUM} && ip link set tun${TUN_NUM} up && exec sleep infinity" &

SSH_PID=$!

# Wait for tun device to appear
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

# Re-apply port forwarding rules (in case iptables was flushed on reboot)
log "Applying port forwarding rules..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1

# DNAT: forward all incoming TCP (except SSH 22) to Kharej
if ! iptables -t nat -C PREROUTING -p tcp -d $LOCAL_IP ! --dport 22 -j DNAT --to-destination $SERVER_TUN_IP 2>/dev/null; then
    iptables -t nat -A PREROUTING -p tcp -d $LOCAL_IP ! --dport 22 -j DNAT --to-destination $SERVER_TUN_IP
fi
# DNAT: forward all incoming UDP to Kharej
if ! iptables -t nat -C PREROUTING -p udp -d $LOCAL_IP -j DNAT --to-destination $SERVER_TUN_IP 2>/dev/null; then
    iptables -t nat -A PREROUTING -p udp -d $LOCAL_IP -j DNAT --to-destination $SERVER_TUN_IP
fi
# MASQUERADE outgoing tunnel traffic
if ! iptables -t nat -C POSTROUTING -o $TUN_DEV -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -o $TUN_DEV -j MASQUERADE
fi
# Allow forwarding
if ! iptables -C FORWARD -o $TUN_DEV -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -o $TUN_DEV -j ACCEPT
fi
if ! iptables -C FORWARD -i $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -i $TUN_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT
fi
log "Port forwarding rules applied"

# Verify tunnel connectivity
log "Testing tunnel connectivity..."
if ping -c 3 -W 3 $SERVER_TUN_IP > /dev/null 2>&1; then
    log "Tunnel is UP - Kharej reachable at $SERVER_TUN_IP"
else
    log "WARNING: Cannot ping Kharej through tunnel (TCP traffic may still work)"
fi

log "========================================="
log "  Tunnel established - Relay mode active"
log "  Local:  $CLIENT_TUN_IP"
log "  Remote: $SERVER_TUN_IP"
log "  All ports -> Kharej (except SSH 22)"
log "========================================="

# Wait for SSH process - when it dies, systemd will restart us
wait $SSH_PID
EXIT_CODE=$?
log "SSH process exited with code $EXIT_CODE"
exit $EXIT_CODE
SCRIPTEOF

    chmod +x $TUNNEL_SCRIPT
    echo -e "${GREEN}  ✓ Tunnel script created: $TUNNEL_SCRIPT${NC}"

    # --- Step 8: Create systemd service ---
    echo -e "${YELLOW}[8/8] Creating systemd service...${NC}"

    cat > /etc/systemd/system/${TUNNEL_SERVICE}.service << SVCEOF
[Unit]
Description=SSH TUN Tunnel to Kharej (Relay Mode)
After=network-online.target
Wants=network-online.target

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
    echo -e "${GREEN}  ✓ Systemd service created and enabled${NC}"

    # Start the tunnel
    echo
    echo -e "${YELLOW}Starting tunnel...${NC}"
    systemctl start $TUNNEL_SERVICE

    # Wait for it to come up
    echo "Waiting for tunnel to establish..."
    sleep 8

    # Check status
    if systemctl is-active --quiet $TUNNEL_SERVICE; then
        if ip link show $TUN_DEV &>/dev/null; then
            echo -e "${GREEN}  ✓ Tunnel service is running${NC}"
            echo -e "${GREEN}  ✓ Tunnel device $TUN_DEV is up${NC}"

            if ping -c 2 -W 3 $SERVER_TUN_IP > /dev/null 2>&1; then
                echo -e "${GREEN}  ✓ Kharej server is reachable through tunnel${NC}"
            else
                echo -e "${YELLOW}  ⚠ Ping to Kharej failed (TCP traffic may still work)${NC}"
            fi
        else
            echo -e "${YELLOW}  ⚠ Tunnel device not yet active, may still be initializing${NC}"
        fi
    else
        echo -e "${RED}  ✗ Tunnel service failed to start${NC}"
        echo "  Check logs: journalctl -u $TUNNEL_SERVICE -n 30 --no-pager"
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
    echo "  SSH tunnel port:    $SSH_PORT"
    echo "  Protocol:           TCP (encrypted SSH)"
    echo
    echo -e "${BLUE}Port Forwarding:${NC}"
    echo "  TCP:  ALL ports forwarded to Kharej (except 22)"
    echo "  UDP:  ALL ports forwarded to Kharej"
    echo
    echo -e "${YELLOW}V2Ray Configuration:${NC}"
    echo "  In your V2Ray client, use this server address:"
    echo "    Address: $LOCAL_IP"
    echo "    Port:    (same port as V2Ray on Kharej)"
    echo "  Traffic will be relayed to Kharej automatically."
    echo
    echo -e "${BLUE}Management Commands:${NC}"
    echo "  Status:   systemctl status $TUNNEL_SERVICE"
    echo "  Logs:     journalctl -u $TUNNEL_SERVICE -f"
    echo "  Stop:     systemctl stop $TUNNEL_SERVICE"
    echo "  Start:    systemctl start $TUNNEL_SERVICE"
    echo "  Restart:  systemctl restart $TUNNEL_SERVICE"
    echo
    echo -e "${BLUE}Or use this script:${NC}"
    echo "  bash setup.sh  (choose option 3 to manage)"
    echo
    exit 0
fi
