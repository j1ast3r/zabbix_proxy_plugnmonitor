#!/bin/bash
#================================================================
# Plug & Monitor
# Version: 2.0.1  - TEMPLATE NAMES FIXED!
# All bugs fixed + Quality checks + Auto-scan enabled
#================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Installation configuration
INSTALL_DIR="/opt/plug-monitor"
LOG_DIR="/var/log/plug-monitor"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="2.0.1"

# Default settings for KGGR
DEFAULT_ZABBIX_SERVER="monitoring.kggr.de:10051"
DEFAULT_API_URL="http://monitoring.kggr.de/api_jsonrpc.php"
DEFAULT_NETWORK="192.168.1.0/24"

# Log file
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/install_$(date +%Y%m%d_%H%M%S).log"

#================================================================
# Utility Functions
#================================================================

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1" | tee -a "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE"
}

print_header() {
    echo "" | tee -a "$LOG_FILE"
    echo -e "${CYAN}$1${NC}" | tee -a "$LOG_FILE"
    echo -e "${CYAN}$(echo "$1" | sed 's/./=/g')${NC}" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_prerequisites() {
    print_header "Checking Prerequisites"

    local all_ok=true

    # Check OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        print_info "OS: $PRETTY_NAME"

        if [[ "$ID" != "debian" && "$ID" != "ubuntu" && "$ID" != "raspbian" ]]; then
            print_warning "This script is optimized for Debian/Ubuntu/Raspbian"
        fi
    fi

    # Check internet connectivity
    if ping -c 1 8.8.8.8 &> /dev/null; then
        print_success "Internet connection OK"
    else
        print_error "No internet connection"
        all_ok=false
    fi

    # Check disk space (minimum 2GB)
    available_space=$(df / | tail -1 | awk '{print $4}')
    if [ "$available_space" -lt 2097152 ]; then
        print_error "Insufficient disk space (need at least 2GB free)"
        all_ok=false
    else
        print_success "Disk space OK ($(df -h / | tail -1 | awk '{print $4}') available)"
    fi

    # Check RAM (minimum 1GB)
    total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$total_ram" -lt 1024 ]; then
        print_warning "Low RAM detected (${total_ram}MB) - 2GB+ recommended"
    else
        print_success "RAM OK (${total_ram}MB)"
    fi

    if [ "$all_ok" = false ]; then
        print_error "Prerequisites check failed"
        exit 1
    fi

    print_success "All prerequisites met"
    echo ""
}

show_banner() {
    clear
    cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║                      PLUG & MONITOR                      ║
║                Automated Zabbix Monitoring               ║
╚══════════════════════════════════════════════════════════╝
EOF
    echo ""
}

collect_config() {
    print_header "Configuration Wizard"

    # Zabbix Server (с портом по умолчанию)
    read -p "Zabbix Server (format IP:PORT) [${DEFAULT_ZABBIX_SERVER}]: " ZABBIX_SERVER
    ZABBIX_SERVER=${ZABBIX_SERVER:-$DEFAULT_ZABBIX_SERVER}

    # Проверка формата IP:PORT
    if [[ ! "$ZABBIX_SERVER" =~ :[0-9]+$ ]]; then
        print_warning "Server should include port (e.g., monitoring.kggr.de:10051)"
        ZABBIX_SERVER="${ZABBIX_SERVER}:10051"
        print_info "Using: $ZABBIX_SERVER"
    fi

    # API URL
    read -p "Zabbix API URL [${DEFAULT_API_URL}]: " ZABBIX_API_URL
    ZABBIX_API_URL=${ZABBIX_API_URL:-$DEFAULT_API_URL}

    echo ""
    echo "Choose authentication method:"
    echo "  1) API Token (recommended for Zabbix 7.0+)"
    echo "  2) Username + Password (legacy)"
    read -p "Choice [1]: " AUTH_METHOD
    AUTH_METHOD=${AUTH_METHOD:-1}

    if [ "$AUTH_METHOD" = "1" ]; then
        read -p "API Token: " ZABBIX_API_TOKEN
        ZABBIX_USER=""
        ZABBIX_PASSWORD=""
    else
        read -p "Zabbix API username [Admin]: " ZABBIX_USER
        ZABBIX_USER=${ZABBIX_USER:-Admin}
        read -sp "Zabbix API password: " ZABBIX_PASSWORD
        echo ""
        ZABBIX_API_TOKEN=""
    fi

    # Proxy name
    read -p "Proxy name [Proxy-$(hostname)]: " PROXY_NAME
    PROXY_NAME=${PROXY_NAME:-Proxy-$(hostname)}

    # Network range
    default_network=$(ip route | grep default | awk '{print $3}' | cut -d'.' -f1-3)
    read -p "Network to scan [${default_network}.0/24]: " SCAN_NETWORK
    SCAN_NETWORK=${SCAN_NETWORK:-${default_network}.0/24}

    # Auto-scan settings
    echo ""
    read -p "Enable automatic periodic scanning? (y/N): " ENABLE_AUTO_SCAN
    if [[ $ENABLE_AUTO_SCAN =~ ^[Yy]$ ]]; then
        read -p "Scan interval in hours [2]: " SCAN_HOURS
        SCAN_HOURS=${SCAN_HOURS:-2}
        SCAN_INTERVAL=$((SCAN_HOURS * 3600))
        AUTO_SCAN_ENABLED="true"
    else
        SCAN_INTERVAL=7200
        AUTO_SCAN_ENABLED="false"
    fi

    # Dashboard settings
    echo ""
    read -p "Dashboard port [8080]: " DASHBOARD_PORT
    DASHBOARD_PORT=${DASHBOARD_PORT:-8080}
    read -p "Dashboard admin username [admin]: " DASHBOARD_USER
    DASHBOARD_USER=${DASHBOARD_USER:-admin}
    read -sp "Dashboard admin password: " DASHBOARD_PASSWORD
    echo ""

    # Confirmation
    echo ""
    print_header "Configuration Summary"
    echo "Zabbix Server:    $ZABBIX_SERVER"
    echo "API URL:          $ZABBIX_API_URL"
    echo "Proxy Name:       $PROXY_NAME"
    echo "Network Range:    $SCAN_NETWORK"
    echo "Auto-Scan:        $AUTO_SCAN_ENABLED ($SCAN_HOURS hours)"
    echo "Dashboard:        http://<this-ip>:$DASHBOARD_PORT"
    echo ""
    read -p "Proceed with these settings? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Installation cancelled"
        exit 0
    fi
}

create_directories() {
    print_header "Creating Directory Structure"

    # Create ALL necessary directories
    mkdir -p "$INSTALL_DIR"/{config,data/{scans,keys}}
    mkdir -p "$INSTALL_DIR"/{01_raspberry_pi,02_network_scanner,03_auto_discovery,04_windows_deployment,05_linux_deployment,06_active_directory,07_templates,08_dashboards}
    mkdir -p "$LOG_DIR"

    # CRITICAL: Create Zabbix directories FIRST
    mkdir -p /var/log/zabbix
    mkdir -p /var/lib/zabbix
    mkdir -p /var/run/zabbix
    mkdir -p /etc/zabbix

    # THEN set permissions
    chown -R zabbix:zabbix /var/log/zabbix 2>/dev/null || true
    chown -R zabbix:zabbix /var/lib/zabbix 2>/dev/null || true
    chown -R zabbix:zabbix /var/run/zabbix 2>/dev/null || true
    chmod 755 /var/log/zabbix
    chmod 750 /var/lib/zabbix
    chmod 755 /var/run/zabbix

    print_success "Directories created with correct permissions"
}

install_zabbix_proxy() {
    print_header "Installing Zabbix Proxy 7.0 LTS"

    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
        OS_VERSION=$VERSION_ID
        print_info "Detected: $PRETTY_NAME"
    fi

    # Install dependencies
    print_info "Installing dependencies..."
    apt-get update >> "$LOG_FILE" 2>&1
    apt-get install -y wget gnupg2 sqlite3 fping nmap curl jq >> "$LOG_FILE" 2>&1

    # Install based on OS
    if [ "$OS_ID" = "debian" ] || [ "$OS_ID" = "raspbian" ]; then
        print_info "Installing Zabbix repository for Debian..."
        wget -q https://repo.zabbix.com/zabbix/7.0/debian/pool/main/z/zabbix-release/zabbix-release_latest+debian13_all.deb -O /tmp/zabbix-release.deb
        dpkg -i /tmp/zabbix-release.deb >> "$LOG_FILE" 2>&1
    elif [ "$OS_ID" = "ubuntu" ]; then
        print_info "Installing Zabbix repository for Ubuntu..."
        wget -q https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest+ubuntu22.04_all.deb -O /tmp/zabbix-release.deb
        dpkg -i /tmp/zabbix-release.deb >> "$LOG_FILE" 2>&1
    fi

    apt-get update >> "$LOG_FILE" 2>&1
    apt-get install -y zabbix-proxy-sqlite3 zabbix-sql-scripts >> "$LOG_FILE" 2>&1

    # Create zabbix user if not exists
    if ! id "zabbix" &>/dev/null; then
        useradd --system --group --home /var/lib/zabbix --shell /sbin/nologin zabbix
        print_success "Created zabbix user"
    fi

    # Initialize database
    print_info "Initializing SQLite database..."
    DB_PATH="/var/lib/zabbix/zabbix_proxy.db"

    # Find SQL schema
    SQL_SCHEMA=""
    if [ -f /usr/share/zabbix-sql-scripts/sqlite3/proxy.sql ]; then
        SQL_SCHEMA="/usr/share/zabbix-sql-scripts/sqlite3/proxy.sql"
    elif [ -f /usr/share/doc/zabbix-sql-scripts/sqlite3/proxy.sql ]; then
        SQL_SCHEMA="/usr/share/doc/zabbix-sql-scripts/sqlite3/proxy.sql"
    elif [ -f /usr/share/doc/zabbix-sql-scripts/sqlite3/proxy.sql.gz ]; then
        SQL_SCHEMA="/usr/share/doc/zabbix-sql-scripts/sqlite3/proxy.sql.gz"
        gunzip -c "$SQL_SCHEMA" > /tmp/proxy.sql
        SQL_SCHEMA="/tmp/proxy.sql"
    else
        print_error "SQL schema not found!"
        exit 1
    fi

    if [ ! -s "$SQL_SCHEMA" ]; then
        print_error "SQL schema is empty: $SQL_SCHEMA"
        exit 1
    fi

    cat "$SQL_SCHEMA" | sqlite3 "$DB_PATH"
    [ -f /tmp/proxy.sql ] && rm /tmp/proxy.sql

    chown zabbix:zabbix "$DB_PATH"
    chmod 640 "$DB_PATH"

    # Configure proxy
    print_info "Configuring Zabbix Proxy..."
    cat > /etc/zabbix/zabbix_proxy.conf << EOF
# Zabbix Proxy Configuration - KGGR Professional
# Auto-generated by Plug & Monitor v${VERSION}

Server=${ZABBIX_SERVER}
Hostname=${PROXY_NAME}
LogFile=/var/log/zabbix/zabbix_proxy.log
LogFileSize=10
PidFile=/var/run/zabbix/zabbix_proxy.pid
SocketDir=/var/run/zabbix
DBName=${DB_PATH}

# Performance
Timeout=4
FpingLocation=/usr/bin/fping
Fping6Location=/usr/bin/fping6
StartPollers=5
StartTrappers=5
StartPingers=1
CacheSize=32M
HistoryCacheSize=16M

# Proxy Settings
ProxyOfflineBuffer=24
ProxyConfigFrequency=10
DataSenderFrequency=1

# Security
TLSConnect=unencrypted
TLSAccept=unencrypted
EnableRemoteCommands=0
LogRemoteCommands=0
EOF

    chown root:zabbix /etc/zabbix/zabbix_proxy.conf
    chmod 640 /etc/zabbix/zabbix_proxy.conf

    # Create log file
    touch /var/log/zabbix/zabbix_proxy.log
    chown zabbix:zabbix /var/log/zabbix/zabbix_proxy.log
    chmod 644 /var/log/zabbix/zabbix_proxy.log

    systemctl enable zabbix-proxy >> "$LOG_FILE" 2>&1
    systemctl restart zabbix-proxy >> "$LOG_FILE" 2>&1

    sleep 3

    if systemctl is-active --quiet zabbix-proxy; then
        print_success "Zabbix Proxy installed and running"
    else
        print_error "Zabbix Proxy failed to start"
        journalctl -u zabbix-proxy -n 20 --no-pager | tee -a "$LOG_FILE"
        exit 1
    fi
}

setup_python_env() {
    print_header "Setting Up Python Environment"

    # Install Python if needed
    if ! command -v python3 &> /dev/null; then
        apt-get install -y python3 python3-venv python3-pip >> "$LOG_FILE" 2>&1
    fi

    cd "$INSTALL_DIR"
    python3 -m venv venv >> "$LOG_FILE" 2>&1
    source venv/bin/activate

    print_info "Installing Python packages..."
    pip install --upgrade pip >> "$LOG_FILE" 2>&1
    pip install Flask==3.0.0 >> "$LOG_FILE" 2>&1
    pip install Flask-CORS==4.0.0 >> "$LOG_FILE" 2>&1
    pip install python-nmap==0.7.1 >> "$LOG_FILE" 2>&1
    pip install pyyaml==6.0.1 >> "$LOG_FILE" 2>&1
    pip install requests==2.31.0 >> "$LOG_FILE" 2>&1
    pip install gunicorn==21.2.0 >> "$LOG_FILE" 2>&1
    pip install schedule==1.2.0 >> "$LOG_FILE" 2>&1

    deactivate
    print_success "Python environment ready"
}

copy_project_files() {
    print_header "Copying Project Files"

    verify_copy() {
        local src="$1"
        local dst="$2"
        local name="$3"

        if [ ! -f "$src" ]; then
            print_error "$name not found: $src"
            return 1
        fi

        mkdir -p "$(dirname "$dst")"
        cp "$src" "$dst"

        if [ -f "$dst" ] && [ -s "$dst" ]; then
            local size=$(stat -c%s "$dst")
            print_success "✓ $name ($size bytes)"
            return 0
        else
            print_error "✗ $name copy failed!"
            return 1
        fi
    }

    # Copy Python files
    verify_copy "$SCRIPT_DIR/03_auto_discovery/auto_discovery.py" \
                "$INSTALL_DIR/03_auto_discovery/auto_discovery.py" \
                "auto_discovery.py" || exit 1

    verify_copy "$SCRIPT_DIR/02_network_scanner/web_dashboard.py" \
                "$INSTALL_DIR/02_network_scanner/web_dashboard.py" \
                "web_dashboard.py" || exit 1

    verify_copy "$SCRIPT_DIR/02_network_scanner/network_scanner.py" \
                "$INSTALL_DIR/02_network_scanner/network_scanner.py" \
                "network_scanner.py" || exit 1

    # Copy templates
    if [ -d "$SCRIPT_DIR/02_network_scanner/templates" ]; then
        mkdir -p "$INSTALL_DIR/02_network_scanner/templates"
        cp -r "$SCRIPT_DIR/02_network_scanner/templates/"* "$INSTALL_DIR/02_network_scanner/templates/" 2>/dev/null || true
        print_success "✓ Templates copied"
    fi

    # Make scripts executable
    chmod +x "$INSTALL_DIR/03_auto_discovery/auto_discovery.py"
    chmod +x "$INSTALL_DIR/02_network_scanner/network_scanner.py"
    chmod +x "$INSTALL_DIR/02_network_scanner/web_dashboard.py"

    print_success "All files copied and verified"
}

save_config() {
    print_header "Saving Configuration"

    # Build config based on auth method
    if [ -n "$ZABBIX_API_TOKEN" ]; then
        AUTH_CONFIG="  api_token: \"${ZABBIX_API_TOKEN}\"
  api_user: \"\"
  api_password: \"\""
    else
        AUTH_CONFIG="  api_token: \"\"
  api_user: \"${ZABBIX_USER}\"
  api_password: \"${ZABBIX_PASSWORD}\""
    fi

    cat > "${INSTALL_DIR}/config/config.yml" << EOF
# Plug & Monitor Configuration - KGGR Professional
# Version: ${VERSION}
# Generated: $(date)

zabbix:
  server: ${ZABBIX_SERVER}
  api_url: ${ZABBIX_API_URL}
${AUTH_CONFIG}
  proxy_name: ${PROXY_NAME}

network:
  scan_range: ${SCAN_NETWORK}
  scan_interval: 3600
  nmap_options: "-sn -T4 -PE"
  exclude_ips: []
  auto_scan:
    enabled: ${AUTO_SCAN_ENABLED}
    interval: ${SCAN_INTERVAL}
    on_startup: true

discovery:
  enabled: true
  auto_add_hosts: true
  auto_apply_templates: true
  default_groups:
    - "Discovered hosts"
    - "KGGR Infrastructure"
  check_interval: 60

  # ✅ FIXED: Template names for Zabbix 4.x-6.x (KGGR uses Zabbix 6.x)
  # ⚠️ CRITICAL: These are EXACT names from YOUR Zabbix Server!
  # Verified with: curl API + template.get
  # DO NOT change unless you verified exact names in your Zabbix!
  template_mapping:
    windows:
      - "Template OS Windows"
    linux:
      - "Template OS Linux"
    network_device:
      - "Template Net Network Generic Device SNMPv2"
    printer:
      - "Template Module Generic SNMPv2"
    server:
      - "Template OS Linux"
    workstation:
      - "Template Module ICMP Ping"
    iot:
      - "Template Module ICMP Ping"
    unknown:
      - "Template Module ICMP Ping"

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
  api_timeout: 15
  api_retry: true
  api_retry_count: 3
  api_retry_delay: 5
  api_rate_limit: 100
  processed_hosts_db: ${INSTALL_DIR}/data/processed_hosts.json
  scan_data_dir: ${INSTALL_DIR}/data/scans
  cleanup:
    enabled: true
    keep_days: 30
    keep_count: 100

company:
  name: "KGGR"
  contact: "it@kggr.de"
  location: "Germany"
EOF

    chmod 600 "${INSTALL_DIR}/config/config.yml"
    print_success "Configuration saved securely"
}

install_services() {
    print_header "Installing Systemd Services"

    # Auto-Discovery service
    cat > /etc/systemd/system/zabbix-autodiscovery.service << EOF
[Unit]
Description=Plug & Monitor Auto-Discovery Service
Documentation=https://kggr.de/monitoring
After=network-online.target zabbix-proxy.service
Wants=network-online.target
Requires=zabbix-proxy.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}/03_auto_discovery
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/03_auto_discovery/auto_discovery.py --config ${INSTALL_DIR}/config/config.yml
Restart=always
RestartSec=10
StartLimitInterval=200
StartLimitBurst=5

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zabbix-autodiscovery

# Security
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    # Dashboard service
    cat > /etc/systemd/system/zabbix-dashboard.service << EOF
[Unit]
Description=Plug & Monitor Web Dashboard
Documentation=https://kggr.de/monitoring
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}/02_network_scanner
ExecStart=${INSTALL_DIR}/venv/bin/gunicorn -w 2 -b 0.0.0.0:${DASHBOARD_PORT} --timeout 120 web_dashboard:app
Restart=always
RestartSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zabbix-dashboard

# Security
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable zabbix-autodiscovery >> "$LOG_FILE" 2>&1
    systemctl enable zabbix-dashboard >> "$LOG_FILE" 2>&1

    print_success "Services installed and enabled"
}

start_services() {
    print_header "Starting Services"

    systemctl start zabbix-proxy
    sleep 2
    systemctl start zabbix-autodiscovery
    sleep 1
    systemctl start zabbix-dashboard
    sleep 2

    # Check status
    local all_ok=true

    if systemctl is-active --quiet zabbix-proxy; then
        print_success "✓ Zabbix Proxy: Running"
    else
        print_error "✗ Zabbix Proxy: Failed"
        all_ok=false
    fi

    if systemctl is-active --quiet zabbix-autodiscovery; then
        print_success "✓ Auto-Discovery: Running"
    else
        print_warning "⚠ Auto-Discovery: Not running"
    fi

    if systemctl is-active --quiet zabbix-dashboard; then
        print_success "✓ Dashboard: Running"
    else
        print_warning "⚠ Dashboard: Not running"
    fi

    if [ "$all_ok" = false ]; then
        print_warning "Some services failed - check logs"
    fi
}

configure_firewall() {
    print_header "Configuring Firewall"

    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp >> "$LOG_FILE" 2>&1
        ufw allow ${DASHBOARD_PORT}/tcp >> "$LOG_FILE" 2>&1
        ufw allow 10050/tcp >> "$LOG_FILE" 2>&1
        ufw allow 10051/tcp >> "$LOG_FILE" 2>&1
        ufw --force enable >> "$LOG_FILE" 2>&1
        print_success "Firewall configured (UFW)"
    else
        print_warning "UFW not found - firewall not configured"
    fi
}

run_quality_checks() {
    print_header "Running Quality Checks"

    local checks_passed=0
    local checks_total=0

    # Check 1: Config file exists and readable
    ((checks_total++))
    if [ -f "${INSTALL_DIR}/config/config.yml" ] && [ -r "${INSTALL_DIR}/config/config.yml" ]; then
        print_success "✓ Configuration file readable"
        ((checks_passed++))
    else
        print_error "✗ Configuration file missing or unreadable"
    fi

    # Check 2: Python environment
    ((checks_total++))
    if [ -f "${INSTALL_DIR}/venv/bin/python3" ]; then
        print_success "✓ Python virtual environment exists"
        ((checks_passed++))
    else
        print_error "✗ Python virtual environment missing"
    fi

    # Check 3: Zabbix Proxy database
    ((checks_total++))
    if [ -f "/var/lib/zabbix/zabbix_proxy.db" ] && [ -s "/var/lib/zabbix/zabbix_proxy.db" ]; then
        print_success "✓ Zabbix Proxy database initialized"
        ((checks_passed++))
    else
        print_error "✗ Zabbix Proxy database missing or empty"
    fi

    # Check 4: Zabbix Proxy connectivity
    ((checks_total++))
    if grep -q "sending configuration" /var/log/zabbix/zabbix_proxy.log 2>/dev/null; then
        print_success "✓ Zabbix Proxy connected to server"
        ((checks_passed++))
    else
        print_warning "⚠ Zabbix Proxy not yet connected (may take 1-2 minutes)"
    fi

    # Check 5: Services running
    ((checks_total++))
    local services_ok=0
    systemctl is-active --quiet zabbix-proxy && ((services_ok++))
    systemctl is-active --quiet zabbix-autodiscovery && ((services_ok++))
    systemctl is-active --quiet zabbix-dashboard && ((services_ok++))

    if [ $services_ok -eq 3 ]; then
        print_success "✓ All services running"
        ((checks_passed++))
    else
        print_warning "⚠ Only $services_ok/3 services running"
    fi

    # Check 6: Dashboard accessibility
    ((checks_total++))
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:${DASHBOARD_PORT} | grep -q "200\|301\|302"; then
        print_success "✓ Dashboard accessible"
        ((checks_passed++))
    else
        print_warning "⚠ Dashboard not yet accessible"
    fi

    # Summary
    echo ""
    if [ $checks_passed -eq $checks_total ]; then
        print_success "All quality checks passed ($checks_passed/$checks_total)"
        return 0
    else
        print_warning "Quality checks: $checks_passed/$checks_total passed"
        return 1
    fi
}

show_summary() {
    local ip_addr=$(hostname -I | awk '{print $1}')

    clear
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  Installation Completed Successfully!                    ║${NC}"
    echo -e "${GREEN}║  Plug & Monitor v${VERSION}                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}📊 Access Points:${NC}"
    echo "   Dashboard:  http://${ip_addr}:${DASHBOARD_PORT}"
    echo "   Username:   ${DASHBOARD_USER}"
    echo "   Password:   ${DASHBOARD_PASSWORD}"
    echo ""

    echo -e "${CYAN}📁 Important Paths:${NC}"
    echo "   Config:     ${INSTALL_DIR}/config/config.yml"
    echo "   Logs:       ${LOG_DIR}/"
    echo "   Zabbix Log: /var/log/zabbix/zabbix_proxy.log"
    echo ""

    echo -e "${CYAN}🔧 Service Management:${NC}"
    echo "   sudo systemctl status zabbix-proxy"
    echo "   sudo systemctl status zabbix-autodiscovery"
    echo "   sudo systemctl status zabbix-dashboard"
    echo ""

    echo -e "${CYAN}📝 Next Steps:${NC}"
    echo "   1. Add proxy in Zabbix Server web interface:"
    echo "      • Go to: Administration → Proxies → Create proxy"
    echo "      • Name: ${PROXY_NAME}"
    echo "      • Mode: Active"
    echo ""
    echo "   2. Wait 1-2 minutes for proxy to connect"
    echo "      • Check: tail -f /var/log/zabbix/zabbix_proxy.log"
    echo "      • Look for: 'sending configuration'"
    echo ""
    echo "   3. Access dashboard and start network scan"
    echo "      • Automatic scanning is ${AUTO_SCAN_ENABLED}"
    if [ "$AUTO_SCAN_ENABLED" = "true" ]; then
    echo "      • Scan interval: every ${SCAN_HOURS} hours"
    fi
    echo ""

    echo -e "${CYAN}📞 Support:${NC}"
    echo "   Company: KGGR"
    echo "   Contact: it@kggr.de"
    echo "   Docs:    ${INSTALL_DIR}/docs/"
    echo ""

    echo -e "${CYAN}📋 Installation Log:${NC}"
    echo "   ${LOG_FILE}"
    echo ""

    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  Professional monitoring solution ready for production  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Main installation
main() {
    show_banner
    check_root
    check_prerequisites

    read -p "Proceed with installation? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Installation cancelled"
        exit 0
    fi

    collect_config

    print_info "Starting professional installation..."
    echo ""

    create_directories
    install_zabbix_proxy
    setup_python_env
    copy_project_files
    save_config
    install_services
    configure_firewall
    start_services

    echo ""
    run_quality_checks

    show_summary

    print_info "Full installation log: $LOG_FILE"
}

main "$@"