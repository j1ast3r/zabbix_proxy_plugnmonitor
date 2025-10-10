#!/bin/bash
# Plug & Monitor - Master Installation Script (FIXED VERSION)
# All bugs from Raspberry Pi installation fixed

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }

# Installation paths
INSTALL_DIR="/opt/plug-monitor"
LOG_DIR="/var/log/plug-monitor"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Log file
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/install_$(date +%Y%m%d_%H%M%S).log"

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Banner
show_banner() {
    clear
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║     PLUG & MONITOR - Installation Wizard                  ║
║          Automated Zabbix Monitoring                      ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo ""
}

# Collect configuration
collect_config() {
    print_info "Configuration Wizard"
    echo ""

    read -p "Zabbix Server IP or hostname: " ZABBIX_SERVER
    read -p "Zabbix API URL [http://${ZABBIX_SERVER}/zabbix/api_jsonrpc.php]: " ZABBIX_API_URL
    ZABBIX_API_URL=${ZABBIX_API_URL:-http://${ZABBIX_SERVER}/zabbix/api_jsonrpc.php}
    read -p "Zabbix API username [Admin]: " ZABBIX_USER
    ZABBIX_USER=${ZABBIX_USER:-Admin}
    read -sp "Zabbix API password: " ZABBIX_PASSWORD
    echo ""

    read -p "Proxy name [PlugMonitor-Proxy-$(hostname)]: " PROXY_NAME
    PROXY_NAME=${PROXY_NAME:-PlugMonitor-Proxy-$(hostname)}

    default_network=$(ip route | grep default | awk '{print $3}' | cut -d'.' -f1-3)
    read -p "Network to scan [${default_network}.0/24]: " SCAN_NETWORK
    SCAN_NETWORK=${SCAN_NETWORK:-${default_network}.0/24}

    read -p "Dashboard port [8080]: " DASHBOARD_PORT
    DASHBOARD_PORT=${DASHBOARD_PORT:-8080}
    read -p "Dashboard admin username [admin]: " DASHBOARD_USER
    DASHBOARD_USER=${DASHBOARD_USER:-admin}
    read -sp "Dashboard admin password: " DASHBOARD_PASSWORD
    echo ""
}

# Create directories - FIXED
create_directories() {
    print_info "Creating directory structure..."

    # Create ALL necessary directories
    mkdir -p "$INSTALL_DIR"/{config,data/{scans,keys}}
    mkdir -p "$INSTALL_DIR"/{01_raspberry_pi,02_network_scanner,03_auto_discovery,04_windows_deployment,05_linux_deployment,06_active_directory,07_templates,08_dashboards}
    mkdir -p "$LOG_DIR"

    # CRITICAL: Create Zabbix directories
    mkdir -p /var/log/zabbix
    mkdir -p /var/lib/zabbix

    # Set permissions
    chown -R zabbix:zabbix /var/log/zabbix 2>/dev/null || true
    chown -R zabbix:zabbix /var/lib/zabbix 2>/dev/null || true
    chmod 755 /var/log/zabbix
    chmod 755 /var/lib/zabbix

    print_success "Directories created"
}

# Install Zabbix Proxy - FIXED
install_zabbix_proxy() {
    print_info "Installing Zabbix Proxy 7.0..."

    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
        OS_VERSION=$VERSION_ID
    fi

    # Install based on OS
    if [ "$OS_ID" = "debian" ] || [ "$OS_ID" = "raspbian" ]; then
        wget -q https://repo.zabbix.com/zabbix/7.0/debian/pool/main/z/zabbix-release/zabbix-release_7.0-2+debian12_all.deb -O /tmp/zabbix-release.deb
        dpkg -i /tmp/zabbix-release.deb >> "$LOG_FILE" 2>&1
        apt-get update >> "$LOG_FILE" 2>&1
        apt-get install -y zabbix-proxy-sqlite3 fping >> "$LOG_FILE" 2>&1
    elif [ "$OS_ID" = "ubuntu" ]; then
        wget -q https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_7.0-2+ubuntu22.04_all.deb -O /tmp/zabbix-release.deb
        dpkg -i /tmp/zabbix-release.deb >> "$LOG_FILE" 2>&1
        apt-get update >> "$LOG_FILE" 2>&1
        apt-get install -y zabbix-proxy-sqlite3 fping >> "$LOG_FILE" 2>&1
    fi

    # Configure proxy
    cat > /etc/zabbix/zabbix_proxy.conf << EOF
Server=${ZABBIX_SERVER}
ServerPort=10051
Hostname=${PROXY_NAME}
LogFile=/var/log/zabbix/zabbix_proxy.log
LogFileSize=10
PidFile=/run/zabbix/zabbix_proxy.pid
SocketDir=/run/zabbix
DBName=/var/lib/zabbix/zabbix_proxy.db
Timeout=4
FpingLocation=/usr/bin/fping
Fping6Location=/usr/bin/fping6

# Performance tuning
StartPollers=5
StartTrappers=5
StartPingers=1
CacheSize=32M
HistoryCacheSize=16M

ProxyOfflineBuffer=24
HeartbeatFrequency=60
ConfigFrequency=300

TLSConnect=unencrypted
TLSAccept=unencrypted
EnableRemoteCommands=0
EOF

    # Ensure database directory exists and has correct permissions
    mkdir -p /var/lib/zabbix
    chown zabbix:zabbix /var/lib/zabbix
    chmod 750 /var/lib/zabbix

    systemctl enable zabbix-proxy >> "$LOG_FILE" 2>&1
    systemctl restart zabbix-proxy >> "$LOG_FILE" 2>&1

    print_success "Zabbix Proxy installed"
}

# Setup Python environment - FIXED
setup_python_env() {
    print_info "Setting up Python environment..."

    cd "$INSTALL_DIR"
    python3 -m venv venv >> "$LOG_FILE" 2>&1
    source venv/bin/activate

    pip install --upgrade pip >> "$LOG_FILE" 2>&1

    # Install Python packages
    pip install Flask==3.0.0 >> "$LOG_FILE" 2>&1
    pip install Flask-CORS==4.0.0 >> "$LOG_FILE" 2>&1
    pip install python-nmap==0.7.1 >> "$LOG_FILE" 2>&1
    pip install pyyaml==6.0.1 >> "$LOG_FILE" 2>&1
    pip install requests==2.31.0 >> "$LOG_FILE" 2>&1
    pip install gunicorn==21.2.0 >> "$LOG_FILE" 2>&1

    deactivate
    print_success "Python environment ready"
}

# Copy project files - FIXED
copy_project_files() {
    print_info "Copying project files..."

    # Copy Python files from script directory to install directory
    if [ -f "$SCRIPT_DIR/03_auto_discovery/auto_discovery.py" ]; then
        cp "$SCRIPT_DIR/03_auto_discovery/auto_discovery.py" "$INSTALL_DIR/03_auto_discovery/"
        print_success "Copied auto_discovery.py"
    else
        print_error "auto_discovery.py not found in $SCRIPT_DIR"
    fi

    if [ -f "$SCRIPT_DIR/02_network_scanner/web_dashboard.py" ]; then
        cp "$SCRIPT_DIR/02_network_scanner/web_dashboard.py" "$INSTALL_DIR/02_network_scanner/"
        print_success "Copied web_dashboard.py"
    else
        print_error "web_dashboard.py not found in $SCRIPT_DIR"
    fi

    if [ -f "$SCRIPT_DIR/02_network_scanner/network_scanner.py" ]; then
        cp "$SCRIPT_DIR/02_network_scanner/network_scanner.py" "$INSTALL_DIR/02_network_scanner/"
        print_success "Copied network_scanner.py"
    else
        print_error "network_scanner.py not found in $SCRIPT_DIR"
    fi

    # Copy templates if they exist
    if [ -d "$SCRIPT_DIR/02_network_scanner/templates" ]; then
        mkdir -p "$INSTALL_DIR/02_network_scanner/templates"
        cp -r "$SCRIPT_DIR/02_network_scanner/templates/"* "$INSTALL_DIR/02_network_scanner/templates/" 2>/dev/null || true
        print_success "Copied templates"
    fi

    # Verify files are not empty
    for file in "$INSTALL_DIR/03_auto_discovery/auto_discovery.py" \
                "$INSTALL_DIR/02_network_scanner/web_dashboard.py" \
                "$INSTALL_DIR/02_network_scanner/network_scanner.py"; do
        if [ -f "$file" ]; then
            size=$(stat -c%s "$file")
            if [ "$size" -eq 0 ]; then
                print_error "$(basename $file) is empty (0 bytes)!"
            else
                print_success "$(basename $file): $size bytes"
            fi
        fi
    done
}

# Save configuration - FIXED
save_config() {
    print_info "Saving configuration..."

    cat > "${INSTALL_DIR}/config/config.yml" << EOF
zabbix:
  server: ${ZABBIX_SERVER}
  server_port: 10051
  api_url: ${ZABBIX_API_URL}
  api_user: ${ZABBIX_USER}
  api_password: ${ZABBIX_PASSWORD}
  proxy_name: ${PROXY_NAME}

network:
  scan_range: ${SCAN_NETWORK}
  scan_interval: 3600
  nmap_options: "-sn -T4"
  exclude_ips: []

discovery:
  enabled: true
  auto_add_hosts: true
  auto_apply_templates: true
  default_groups:
    - "Discovered hosts"
    - "PlugMonitor"
  check_interval: 60
  template_mapping:
    windows:
      - "Windows by Zabbix agent active"
    linux:
      - "Linux by Zabbix agent active"
    network_device:
      - "Generic SNMP"
    unknown:
      - "ICMP Ping"

dashboard:
  host: 0.0.0.0
  port: ${DASHBOARD_PORT}
  admin_user: ${DASHBOARD_USER}
  admin_password: ${DASHBOARD_PASSWORD}
  secret_key: $(openssl rand -hex 32)

automation_level: 2

logging:
  level: INFO
  file: ${LOG_DIR}/plug-monitor.log
  max_size: 10485760
  backup_count: 5

advanced:
  api_timeout: 10
  processed_hosts_db: ${INSTALL_DIR}/data/processed_hosts.json
  scan_data_dir: ${INSTALL_DIR}/data/scans
EOF

    chmod 600 "${INSTALL_DIR}/config/config.yml"
    print_success "Configuration saved"
}

# Install systemd services - FIXED
install_services() {
    print_info "Installing systemd services..."

    # Auto-Discovery service
    cat > /etc/systemd/system/zabbix-autodiscovery.service << EOF
[Unit]
Description=Zabbix Auto-Discovery Service
After=network.target zabbix-proxy.service
Requires=zabbix-proxy.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/03_auto_discovery
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/03_auto_discovery/auto_discovery.py --config ${INSTALL_DIR}/config/config.yml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Dashboard service
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

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable zabbix-autodiscovery >> "$LOG_FILE" 2>&1
    systemctl enable zabbix-dashboard >> "$LOG_FILE" 2>&1

    print_success "Services installed"
}

# Start services - FIXED
start_services() {
    print_info "Starting services..."

    systemctl start zabbix-proxy
    sleep 2
    systemctl start zabbix-autodiscovery
    systemctl start zabbix-dashboard

    sleep 3

    # Check status
    if systemctl is-active --quiet zabbix-proxy; then
        print_success "Zabbix Proxy: Running"
    else
        print_error "Zabbix Proxy: Failed"
    fi

    if systemctl is-active --quiet zabbix-autodiscovery; then
        print_success "Auto-Discovery: Running"
    else
        print_warning "Auto-Discovery: Not running (check logs)"
    fi

    if systemctl is-active --quiet zabbix-dashboard; then
        print_success "Dashboard: Running"
    else
        print_warning "Dashboard: Not running (check logs)"
    fi
}

# Configure firewall
configure_firewall() {
    print_info "Configuring firewall..."

    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp >> "$LOG_FILE" 2>&1
        ufw allow ${DASHBOARD_PORT}/tcp >> "$LOG_FILE" 2>&1
        ufw allow 10050/tcp >> "$LOG_FILE" 2>&1
        ufw allow 10051/tcp >> "$LOG_FILE" 2>&1
        ufw --force enable >> "$LOG_FILE" 2>&1
        print_success "Firewall configured (UFW)"
    fi
}

# Final summary
show_summary() {
    local ip_addr=$(hostname -I | awk '{print $1}')

    clear
    echo ""
    print_success "═══════════════════════════════════════════════════════"
    print_success "     Installation completed successfully! 🎉"
    print_success "═══════════════════════════════════════════════════════"
    echo ""
    echo "📊 Access Dashboard:"
    echo "   http://${ip_addr}:${DASHBOARD_PORT}"
    echo ""
    echo "📁 Important paths:"
    echo "   Config: ${INSTALL_DIR}/config/config.yml"
    echo "   Logs: ${LOG_DIR}/"
    echo ""
    echo "🔧 Check service status:"
    echo "   sudo systemctl status zabbix-proxy"
    echo "   sudo systemctl status zabbix-autodiscovery"
    echo "   sudo systemctl status zabbix-dashboard"
    echo ""
    echo "⚠️  Next steps:"
    echo "   1. Add proxy in Zabbix Server web interface"
    echo "      Name: ${PROXY_NAME}"
    echo "      Mode: Active"
    echo "   2. Access dashboard and start network scan"
    echo ""
    print_success "═══════════════════════════════════════════════════════"
}

# Main installation
main() {
    show_banner
    check_root

    read -p "Proceed with installation? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi

    collect_config

    print_info "Starting installation..."
    echo ""

    create_directories
    install_zabbix_proxy
    setup_python_env
    copy_project_files
    save_config
    install_services
    configure_firewall
    start_services

    show_summary

    print_info "Installation log: $LOG_FILE"
}

main "$@"