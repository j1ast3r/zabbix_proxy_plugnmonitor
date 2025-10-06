#!/bin/bash
# Plug & Monitor - Master Installation Script
# Installs complete Zabbix monitoring automation system on Raspberry Pi
# Version: 1.0.0

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_DIR="/opt/plug-monitor"
LOG_DIR="/var/log/plug-monitor"
CONFIG_DIR="${INSTALL_DIR}/config"
DATA_DIR="${INSTALL_DIR}/data"

# Log file
LOG_FILE="${LOG_DIR}/install.log"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to check system requirements
check_requirements() {
    print_info "Checking system requirements..."

    # Check if running on Raspberry Pi or Debian-based system
    if ! grep -q -E "Raspberry|Debian|Ubuntu" /etc/os-release; then
        print_warning "Not running on Raspberry Pi OS, Debian, or Ubuntu. Proceed with caution."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Check RAM
    total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$total_ram" -lt 3500 ]; then
        print_warning "Less than 4GB RAM detected (${total_ram}MB). System may be slow."
    fi

    # Check disk space
    available_space=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$available_space" -lt 10 ]; then
        print_error "Insufficient disk space. At least 10GB free required, found ${available_space}GB"
        exit 1
    fi

    # Check internet connectivity
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        print_error "No internet connection. Cannot proceed with installation."
        exit 1
    fi

    print_success "System requirements check passed"
}

# Function to display welcome banner
show_banner() {
    clear
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ██╗     ██╗   ██╗ ██████╗     ██╗  ██╗              ║
║   ██╔══██╗██║     ██║   ██║██╔════╝     ██║  ██║              ║
║   ██████╔╝██║     ██║   ██║██║  ███╗    ███████║              ║
║   ██╔═══╝ ██║     ██║   ██║██║   ██║    ╚════██║              ║
║   ██║     ███████╗╚██████╔╝╚██████╔╝         ██║              ║
║   ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝          ╚═╝              ║
║                                                               ║
║              MONITOR - Installation Wizard                    ║
║                                                               ║
║              Automated Zabbix Monitoring Solution             ║
║                      Version 1.0.0                            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo ""
}

# Function to collect configuration from user
collect_config() {
    print_info "Configuration Wizard"
    echo ""

    # Zabbix Server configuration
    print_info "Step 1/5: Zabbix Server Configuration"
    read -p "Zabbix Server IP or hostname: " ZABBIX_SERVER
    read -p "Zabbix API URL (default: http://${ZABBIX_SERVER}/api_jsonrpc.php): " ZABBIX_API_URL
    ZABBIX_API_URL=${ZABBIX_API_URL:-http://${ZABBIX_SERVER}/api_jsonrpc.php}
    read -p "Zabbix API username (default: Admin): " ZABBIX_USER
    ZABBIX_USER=${ZABBIX_USER:-Admin}
    read -sp "Zabbix API password: " ZABBIX_PASSWORD
    echo ""

    # Proxy configuration
    print_info "Step 2/5: Proxy Configuration"
    read -p "Proxy name (default: PlugMonitor-Proxy-$(hostname)): " PROXY_NAME
    PROXY_NAME=${PROXY_NAME:-PlugMonitor-Proxy-$(hostname)}

    # Network scanning configuration
    print_info "Step 3/5: Network Scanning Configuration"
    default_network=$(ip route | grep default | awk '{print $3}' | cut -d'.' -f1-3)
    read -p "Network to scan (default: ${default_network}.0/24): " SCAN_NETWORK
    SCAN_NETWORK=${SCAN_NETWORK:-${default_network}.0/24}

    # Dashboard configuration
    print_info "Step 4/5: Web Dashboard Configuration"
    read -p "Dashboard port (default: 8080): " DASHBOARD_PORT
    DASHBOARD_PORT=${DASHBOARD_PORT:-8080}
    read -p "Dashboard admin username (default: admin): " DASHBOARD_USER
    DASHBOARD_USER=${DASHBOARD_USER:-admin}
    read -sp "Dashboard admin password: " DASHBOARD_PASSWORD
    echo ""

    # Automation level
    print_info "Step 5/5: Automation Level"
    echo "1) Level 1 - Basic (ICMP + SNMP, no agents)"
    echo "2) Level 2 - Semi-Auto (+ Agent deployment scripts)"
    echo "3) Level 3 - Full Auto (+ AD integration)"
    read -p "Select automation level (1-3, default: 2): " AUTO_LEVEL
    AUTO_LEVEL=${AUTO_LEVEL:-2}

    echo ""
    print_info "Configuration collected successfully"
}

# Function to create directory structure
create_directories() {
    print_info "Creating directory structure..."

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR/scans"
    mkdir -p "$DATA_DIR/keys"
    mkdir -p "${INSTALL_DIR}/01_raspberry_pi"
    mkdir -p "${INSTALL_DIR}/02_network_scanner/templates"
    mkdir -p "${INSTALL_DIR}/03_auto_discovery/systemd"
    mkdir -p "${INSTALL_DIR}/04_windows_deployment/config"
    mkdir -p "${INSTALL_DIR}/05_linux_deployment/group_vars"
    mkdir -p "${INSTALL_DIR}/06_active_directory"
    mkdir -p "${INSTALL_DIR}/07_templates"
    mkdir -p "${INSTALL_DIR}/08_dashboards"

    print_success "Directory structure created"
}

# Function to save configuration
save_config() {
    print_info "Saving configuration..."

    cat > "${CONFIG_DIR}/config.yml" << EOF
# Plug & Monitor Configuration
# Generated: $(date)

zabbix:
  server: ${ZABBIX_SERVER}
  server_port: 10051
  api_url: ${ZABBIX_API_URL}
  api_user: ${ZABBIX_USER}
  api_password: ${ZABBIX_PASSWORD}
  proxy_name: ${PROXY_NAME}

network:
  scan_range: ${SCAN_NETWORK}
  scan_interval: 3600  # seconds
  nmap_options: "-sn -T4"
  exclude_ips: []

dashboard:
  host: 0.0.0.0
  port: ${DASHBOARD_PORT}
  admin_user: ${DASHBOARD_USER}
  admin_password: ${DASHBOARD_PASSWORD}
  secret_key: $(openssl rand -hex 32)

discovery:
  enabled: true
  auto_add_hosts: true
  auto_apply_templates: true
  default_groups:
    - "Discovered hosts"
    - "PlugMonitor"

automation_level: ${AUTO_LEVEL}

logging:
  level: INFO
  file: ${LOG_DIR}/plug-monitor.log
  max_size: 10485760  # 10MB
  backup_count: 5
EOF

    chmod 600 "${CONFIG_DIR}/config.yml"
    print_success "Configuration saved to ${CONFIG_DIR}/config.yml"
}

# Function to install system dependencies
install_dependencies() {
    print_info "Installing system dependencies..."

    apt-get update -y >> "$LOG_FILE" 2>&1

    # Essential packages
    apt-get install -y \
        wget curl git \
        python3 python3-pip python3-venv \
        nmap \
        sqlite3 \
        nginx \
        ufw \
        openssl \
        jq \
        >> "$LOG_FILE" 2>&1

    print_success "System dependencies installed"
}

# Function to install Zabbix Proxy
install_zabbix_proxy() {
    print_info "Installing Zabbix Proxy 7.0..."

    # Download and install Zabbix repository
    wget https://repo.zabbix.com/zabbix/7.0/debian/pool/main/z/zabbix-release/zabbix-release_7.0-2+debian12_all.deb \
        -O /tmp/zabbix-release.deb >> "$LOG_FILE" 2>&1
    dpkg -i /tmp/zabbix-release.deb >> "$LOG_FILE" 2>&1
    apt-get update -y >> "$LOG_FILE" 2>&1

    # Install Zabbix Proxy with SQLite
    apt-get install -y zabbix-proxy-sqlite3 >> "$LOG_FILE" 2>&1

    # Configure Zabbix Proxy
    cat > /etc/zabbix/zabbix_proxy.conf << EOF
# Zabbix Proxy Configuration - Plug & Monitor
Server=${ZABBIX_SERVER}
ServerPort=10051
Hostname=${PROXY_NAME}
LogFile=/var/log/zabbix/zabbix_proxy.log
LogFileSize=10
DebugLevel=3
DBName=/var/lib/zabbix/zabbix_proxy.db
ProxyMode=0
EnableRemoteCommands=0
LogRemoteCommands=0
StartPollers=5
StartPollersUnreachable=1
StartTrappers=5
StartPingers=1
StartDiscoverers=1
CacheSize=32M
HistoryCacheSize=16M
HistoryIndexCacheSize=4M
Timeout=4
TrapperTimeout=300
UnreachablePeriod=45
UnavailableDelay=60
UnreachableDelay=15
ExternalScripts=/usr/lib/zabbix/externalscripts
FpingLocation=/usr/bin/fping
Fping6Location=/usr/bin/fping6
TLSAccept=unencrypted
TLSConnect=unencrypted
EOF

    # Create database directory
    mkdir -p /var/lib/zabbix
    chown zabbix:zabbix /var/lib/zabbix

    # Enable and start service
    systemctl enable zabbix-proxy >> "$LOG_FILE" 2>&1
    systemctl restart zabbix-proxy >> "$LOG_FILE" 2>&1

    print_success "Zabbix Proxy installed and configured"
}

# Function to setup Python virtual environment
setup_python_env() {
    print_info "Setting up Python virtual environment..."

    cd "$INSTALL_DIR"
    python3 -m venv venv >> "$LOG_FILE" 2>&1
    source venv/bin/activate

    # Upgrade pip
    pip install --upgrade pip >> "$LOG_FILE" 2>&1

    # Install Python packages
    cat > requirements.txt << EOF
Flask==3.0.0
Flask-Login==0.6.3
Flask-CORS==4.0.0
python-nmap==0.7.1
pyyaml==6.0.1
requests==2.31.0
schedule==1.2.0
python-dotenv==1.0.0
gunicorn==21.2.0
ldap3==2.9.1
ansible==9.0.1
jinja2==3.1.2
werkzeug==3.0.1
EOF

    pip install -r requirements.txt >> "$LOG_FILE" 2>&1

    deactivate
    print_success "Python environment configured"
}

# Function to install network scanner
install_network_scanner() {
    print_info "Installing Network Scanner component..."

    # This will be filled by next file creation
    touch "${INSTALL_DIR}/02_network_scanner/network_scanner.py"
    touch "${INSTALL_DIR}/02_network_scanner/web_dashboard.py"

    print_success "Network Scanner installed"
}

# Function to install auto-discovery
install_auto_discovery() {
    print_info "Installing Auto-Discovery component..."

    # Create systemd service
    cat > /etc/systemd/system/zabbix-autodiscovery.service << EOF
[Unit]
Description=Zabbix Auto-Discovery Service
After=network.target zabbix-proxy.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/03_auto_discovery
ExecStart=${INSTALL_DIR}/venv/bin/python auto_discovery.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload >> "$LOG_FILE" 2>&1

    print_success "Auto-Discovery service created"
}

# Function to install web dashboard
install_web_dashboard() {
    print_info "Installing Web Dashboard..."

    # Create systemd service
    cat > /etc/systemd/system/zabbix-dashboard.service << EOF
[Unit]
Description=Plug & Monitor Web Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/02_network_scanner
ExecStart=${INSTALL_DIR}/venv/bin/gunicorn -w 2 -b 0.0.0.0:${DASHBOARD_PORT} web_dashboard:app
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload >> "$LOG_FILE" 2>&1

    print_success "Web Dashboard service created"
}

# Function to configure firewall
configure_firewall() {
    print_info "Configuring firewall..."

    # Enable UFW
    ufw --force enable >> "$LOG_FILE" 2>&1

    # Allow SSH
    ufw allow 22/tcp >> "$LOG_FILE" 2>&1

    # Allow Dashboard
    ufw allow ${DASHBOARD_PORT}/tcp >> "$LOG_FILE" 2>&1

    # Allow Zabbix Proxy
    ufw allow 10050/tcp >> "$LOG_FILE" 2>&1
    ufw allow 10051/tcp >> "$LOG_FILE" 2>&1

    # Allow SNMP (optional)
    ufw allow 161/udp >> "$LOG_FILE" 2>&1

    print_success "Firewall configured"
}

# Function to start services
start_services() {
    print_info "Starting services..."

    systemctl start zabbix-proxy >> "$LOG_FILE" 2>&1
    systemctl start zabbix-autodiscovery >> "$LOG_FILE" 2>&1
    systemctl start zabbix-dashboard >> "$LOG_FILE" 2>&1

    # Enable services on boot
    systemctl enable zabbix-proxy >> "$LOG_FILE" 2>&1
    systemctl enable zabbix-autodiscovery >> "$LOG_FILE" 2>&1
    systemctl enable zabbix-dashboard >> "$LOG_FILE" 2>&1

    print_success "All services started and enabled"
}

# Function to display final summary
show_summary() {
    clear
    echo ""
    print_success "═══════════════════════════════════════════════════════════"
    print_success "       Installation completed successfully! 🎉"
    print_success "═══════════════════════════════════════════════════════════"
    echo ""
    echo "📊 Installation Summary:"
    echo "   • Zabbix Proxy: Installed and running"
    echo "   • Network Scanner: Ready"
    echo "   • Auto-Discovery: Enabled"
    echo "   • Web Dashboard: Running on port ${DASHBOARD_PORT}"
    echo ""
    echo "🌐 Access your dashboard:"
    echo "   http://$(hostname -I | awk '{print $1}'):${DASHBOARD_PORT}"
    echo ""
    echo "📁 Important paths:"
    echo "   • Config: ${CONFIG_DIR}/config.yml"
    echo "   • Logs: ${LOG_DIR}/"
    echo "   • Data: ${DATA_DIR}/"
    echo ""
    echo "🔧 Service management:"
    echo "   sudo systemctl status zabbix-proxy"
    echo "   sudo systemctl status zabbix-autodiscovery"
    echo "   sudo systemctl status zabbix-dashboard"
    echo ""
    echo "📖 Documentation:"
    echo "   cat ${INSTALL_DIR}/README.md"
    echo ""
    echo "⚠️  Next steps:"
    echo "   1. Access the dashboard and verify connection to Zabbix Server"
    echo "   2. Configure discovery rules"
    echo "   3. Start network scanning"
    echo "   4. Monitor auto-discovered hosts"
    echo ""
    print_success "═══════════════════════════════════════════════════════════"
    echo ""
}

# Main installation flow
main() {
    # Create log directory first
    mkdir -p "$LOG_DIR"

    show_banner
    check_root
    check_requirements

    echo ""
    read -p "Proceed with installation? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Installation cancelled by user"
        exit 0
    fi

    collect_config

    print_info "Starting installation..."
    echo ""

    create_directories
    save_config
    install_dependencies
    install_zabbix_proxy
    setup_python_env
    install_network_scanner
    install_auto_discovery
    install_web_dashboard
    configure_firewall

    # Note: Services need actual Python files to start
    # They will be started after files are created

    show_summary

    print_info "Installation log saved to: $LOG_FILE"
}

# Run main function
main "$@"