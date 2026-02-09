#!binbash

# GRE Tunnel Setup Script
# Usage bash (curl -Ls httpsraw.githubusercontent.comYOUR_USERNAMEgre-tunnel-setupmainsetup.sh)

# Colors for better readability
RED='033[0;31m'
GREEN='033[0;32m'
YELLOW='033[1;33m'
BLUE='033[0;34m'
NC='033[0m' # No Color

clear
echo -e ${BLUE}================================${NC}
echo -e ${BLUE}   GRE Tunnel Setup Script${NC}
echo -e ${BLUE}================================${NC}
echo
echo Select server type
echo 1. Iran Server (Client)
echo 2. Kharej Server (ForeignGateway)
echo 3. Cancel
echo
read -p Enter your choice (1-3)  SERVER_TYPE

case $SERVER_TYPE in
    1)
        echo -e ${GREEN}Setting up Iran server...${NC}
        MODE=iran
        ;;
    2)
        echo -e ${GREEN}Setting up Kharej server...${NC}
        MODE=kharej
        ;;
    3)
        echo Setup cancelled
        exit 0
        ;;
    )
        echo -e ${RED}Invalid choice. Exiting.${NC}
        exit 1
        ;;
esac

echo

# Check if running as root
if [ $EUID -ne 0 ]; then 
    echo -e ${RED}Please run as root (use sudo)${NC}
    exit 1
fi

# Auto-detect local IP
LOCAL_IP=$(ip route get 8.8.8.8 2devnull  awk '{print $7; exit}')

if [ -z $LOCAL_IP ]; then
    echo -e ${RED}Error Could not auto-detect local IP${NC}
    read -p Enter local IP manually  LOCAL_IP
    if [ -z $LOCAL_IP ]; then
        echo -e ${RED}Local IP is required. Exiting.${NC}
        exit 1
    fi
fi

echo -e ${GREEN}Detected Local IP $LOCAL_IP${NC}

# Get user inputs
read -p Enter remote server IP  REMOTE_IP
read -p Enter tunnel name (default gre1)  TUNNEL_NAME
TUNNEL_NAME=${TUNNEL_NAME-gre1}

if [ -z $REMOTE_IP ]; then
    echo -e ${RED}Error Remote IP cannot be empty${NC}
    exit 1
fi

# Display configuration summary
echo
echo -e ${YELLOW}=== Configuration Summary ===${NC}
if [ $MODE == iran ]; then
    echo Server Type Iran (Client)
    echo Iran IP (Local) $LOCAL_IP
    echo Kharej IP (Remote) $REMOTE_IP
    echo Tunnel IP 10.10.0.230
    echo Gateway IP 10.10.0.1
else
    echo Server Type Kharej (Gateway)
    echo Kharej IP (Local) $LOCAL_IP
    echo Iran IP (Remote) $REMOTE_IP
    echo Tunnel IP 10.10.0.130
    echo Client IP 10.10.0.2
fi
echo Tunnel Name $TUNNEL_NAME
echo
read -p Proceed with setup (yn)  CONFIRM

if [ $CONFIRM != y ] && [ $CONFIRM != Y ]; then
    echo Setup cancelled
    exit 0
fi

echo

# Remove existing tunnel if exists
if ip link show $TUNNEL_NAME &devnull; then
    echo -e ${YELLOW}Removing existing tunnel $TUNNEL_NAME...${NC}
    ip link set $TUNNEL_NAME down 2devnull
    ip tunnel del $TUNNEL_NAME 2devnull
fi

# Create GRE tunnel (common for both)
echo -e ${YELLOW}Creating GRE tunnel...${NC}
ip tunnel add $TUNNEL_NAME mode gre remote $REMOTE_IP local $LOCAL_IP ttl 225

if [ $ -ne 0 ]; then
    echo -e ${RED}Failed to create tunnel${NC}
    exit 1
fi

if [ $MODE == iran ]; then
    # Iran Server Setup
    ip addr add 10.10.0.230 dev $TUNNEL_NAME
    ip link set $TUNNEL_NAME up
    
    echo -e ${YELLOW}Testing tunnel connectivity...${NC}
    sleep 2
    if ping -c 4 -W 2 10.10.0.1  devnull 2&1; then
        echo -e ${GREEN}✓ Tunnel is UP${NC}
    else
        echo -e ${RED}✗ Warning Tunnel ping failed (Kharej server may not be ready)${NC}
    fi
    
    # Detect gateway
    GATEWAY=$(ip route  grep default  awk '{print $3; exit}')
    if [ -z $GATEWAY ]; then
        echo -e ${RED}Error Could not detect gateway${NC}
        read -p Enter gateway IP manually  GATEWAY
        if [ -z $GATEWAY ]; then
            echo -e ${RED}Gateway is required. Exiting.${NC}
            exit 1
        fi
    fi
    
    echo -e ${YELLOW}Applying routes...${NC}
    echo Gateway $GATEWAY
    
    # Apply Iran IPs routing
    echo Downloading Iran IPs script...
    bash (curl -fsSL httpsraw.githubusercontent.comrezvanniazigretunnelmainiranips.sh) $GATEWAY 2devnull
    
    # Route remote server via gateway (prevent routing loop)
    ip route add $REMOTE_IP via $GATEWAY 2devnull  echo Route already exists
    
    # Set default route through tunnel
    ip route replace default via 10.10.0.1
    
    echo
    echo -e ${GREEN}✓ Iran server setup complete!${NC}
    echo
    echo -e ${BLUE}To monitor tunnel${NC}
    echo   screen -S ping-test
    echo   ping 10.10.0.1
    echo
    echo -e ${BLUE}To check routes${NC}
    echo   ip route show
    
else
    # Kharej Server Setup
    ip addr add 10.10.0.130 dev $TUNNEL_NAME
    ip link set $TUNNEL_NAME up
    
    echo -e ${YELLOW}Testing tunnel connectivity...${NC}
    sleep 2
    if ping -c 4 -W 2 10.10.0.2  devnull 2&1; then
        echo -e ${GREEN}✓ Tunnel is UP${NC}
    else
        echo -e ${YELLOW}⚠ Tunnel ping failed (Iran server may not be configured yet)${NC}
    fi
    
    # Detect main interface
    MAIN_INTERFACE=$(ip route  grep default  awk '{print $5; exit}')
    if [ -z $MAIN_INTERFACE ]; then
        echo -e ${RED}Error Could not detect main interface${NC}
        read -p Enter main interface manually (e.g., eth0)  MAIN_INTERFACE
        if [ -z $MAIN_INTERFACE ]; then
            echo -e ${RED}Interface is required. Exiting.${NC}
            exit 1
        fi
    fi
    
    echo -e ${YELLOW}Enabling IP forwarding...${NC}
    # Enable IP forwarding
    if ! grep -q ^net.ipv4.ip_forward=1 etcsysctl.conf 2devnull; then
        echo net.ipv4.ip_forward=1  etcsysctl.conf
        sysctl -p  devnull 2&1
        echo -e ${GREEN}✓ IP forwarding enabled${NC}
    else
        sysctl -w net.ipv4.ip_forward=1  devnull 2&1
        echo -e ${GREEN}✓ IP forwarding already enabled${NC}
    fi
    
    # Setup NAT
    echo -e ${YELLOW}Configuring iptables NAT...${NC}
    echo Interface $MAIN_INTERFACE
    
    # Check if rule already exists
    if ! iptables -t nat -C POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE 2devnull; then
        iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE
        echo -e ${GREEN}✓ NAT rule added${NC}
    else
        echo -e ${GREEN}✓ NAT rule already exists${NC}
    fi
    
    echo
    echo -e ${GREEN}✓ Kharej server setup complete!${NC}
    echo
    echo -e ${BLUE}Tunnel Information${NC}
    echo   This server (Kharej) 10.10.0.1
    echo   Iran server 10.10.0.2
    echo
    echo -e ${YELLOW}Important Save iptables rules to persist after reboot${NC}
    echo   DebianUbuntu apt install iptables-persistent && netfilter-persistent save
    echo   RHELCentOS service iptables save
fi

echo
echo -e ${BLUE}================================${NC}
echo -e ${GREEN}Setup completed successfully!${NC}
echo -e ${BLUE}================================${NC}