#!/bin/bash
#================================================================
# Zabbix Proxy Installation Script - FULLY FIXED VERSION
# Installs Zabbix 7.0 LTS Proxy on Raspberry Pi
# All bugs fixed for Debian 13 "trixie"
#================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Check root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run with sudo"
   exit 1
fi

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Zabbix Proxy 7.0 Installation${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

#================================================================
# 1. Install dependencies
#================================================================
log_info "Installing dependencies..."
apt-get update
apt-get install -y wget gnupg2 software-properties-common sqlite3 fping
log_success "Dependencies installed"

#================================================================
# 2. Add Zabbix repository
#================================================================
log_info "Adding Zabbix 7.0 LTS repository..."
DEBIAN_CODENAME=$(lsb_release -cs)
log_info "Detected Debian version: $DEBIAN_CODENAME"

# Download repository package
wget "https://repo.zabbix.com/zabbix/7.0/debian/pool/main/z/zabbix-release/zabbix-release_latest+debian13_all.deb" -O /tmp/zabbix-release.deb

if [ ! -f /tmp/zabbix-release.deb ] || [ ! -s /tmp/zabbix-release.deb ]; then
    log_error "Failed to download Zabbix repository package"
    exit 1
fi

dpkg -i /tmp/zabbix-release.deb
rm /tmp/zabbix-release.deb
apt-get update

log_success "Zabbix repository added"

#================================================================
# 3. Install Zabbix Proxy
#================================================================
log_info "Installing Zabbix Proxy (SQLite3)..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    zabbix-proxy-sqlite3 \
    zabbix-sql-scripts

log_success "Zabbix Proxy installed"

#================================================================
# 4. Create user and directories - FIXED!
#================================================================
log_info "Creating zabbix user..."

if ! id "zabbix" &>/dev/null; then
    useradd --system --group --home /var/lib/zabbix --shell /sbin/nologin zabbix
    log_success "User zabbix created"
else
    log_success "User zabbix already exists"
fi

# CRITICAL FIX: Create directories BEFORE setting permissions!
log_info "Creating all required directories..."

mkdir -p /var/log/zabbix
mkdir -p /var/lib/zabbix
mkdir -p /var/run/zabbix
mkdir -p /etc/zabbix

log_success "Directories created"

# Now set permissions
log_info "Setting permissions..."

chown -R zabbix:zabbix /var/log/zabbix
chown -R zabbix:zabbix /var/lib/zabbix
chown -R zabbix:zabbix /var/run/zabbix

chmod 755 /var/log/zabbix
chmod 750 /var/lib/zabbix
chmod 755 /var/run/zabbix

log_success "Permissions set"

#================================================================
# 5. Initialize SQLite database - FIXED!
#================================================================
log_info "Initializing SQLite database..."

DB_PATH="/var/lib/zabbix/zabbix_proxy.db"

# FIX: Check multiple possible paths for SQL schema
SQL_SCHEMA=""

if [ -f /usr/share/zabbix-sql-scripts/sqlite3/proxy.sql ]; then
    SQL_SCHEMA="/usr/share/zabbix-sql-scripts/sqlite3/proxy.sql"
    log_info "Found SQL schema: $SQL_SCHEMA"
elif [ -f /usr/share/doc/zabbix-sql-scripts/sqlite3/proxy.sql ]; then
    SQL_SCHEMA="/usr/share/doc/zabbix-sql-scripts/sqlite3/proxy.sql"
    log_info "Found SQL schema: $SQL_SCHEMA"
elif [ -f /usr/share/doc/zabbix-sql-scripts/sqlite3/proxy.sql.gz ]; then
    SQL_SCHEMA="/usr/share/doc/zabbix-sql-scripts/sqlite3/proxy.sql.gz"
    log_info "Found compressed SQL schema: $SQL_SCHEMA"
    # Decompress
    gunzip -c "$SQL_SCHEMA" > /tmp/proxy.sql
    SQL_SCHEMA="/tmp/proxy.sql"
else
    log_error "SQL schema not found!"
    log_error "Searched in:"
    log_error "  /usr/share/zabbix-sql-scripts/sqlite3/"
    log_error "  /usr/share/doc/zabbix-sql-scripts/sqlite3/"
    exit 1
fi

# Check that schema is not empty
if [ ! -s "$SQL_SCHEMA" ]; then
    log_error "SQL schema is empty: $SQL_SCHEMA"
    exit 1
fi

# Create database
cat "$SQL_SCHEMA" | sqlite3 "$DB_PATH"

# Cleanup temporary file
[ -f /tmp/proxy.sql ] && rm /tmp/proxy.sql

# Set database permissions
chown zabbix:zabbix "$DB_PATH"
chmod 640 "$DB_PATH"

log_success "Database initialized"

#================================================================
# 6. Create configuration file - FIXED!
#================================================================
log_info "Creating configuration file..."

ZABBIX_SERVER=${ZABBIX_SERVER:-"192.168.1.100"}
PROXY_NAME=${PROXY_NAME:-"PlugMonitor-Proxy-$(hostname)"}

log_info "Zabbix Server: $ZABBIX_SERVER"
log_info "Proxy Name: $PROXY_NAME"

# CRITICAL FIX: Removed HeartbeatFrequency (doesn't exist in Zabbix 7.0)
cat > /etc/zabbix/zabbix_proxy.conf << EOF
# Zabbix Proxy Configuration File
# Automatically generated by Plug & Monitor

############ GENERAL PARAMETERS #################

ProxyMode=0
Server=$ZABBIX_SERVER
Hostname=$PROXY_NAME
ListenPort=10051

############ ADVANCED PARAMETERS #################

PidFile=/var/run/zabbix/zabbix_proxy.pid
LogFile=/var/log/zabbix/zabbix_proxy.log
LogFileSize=10
DebugLevel=3

############ DATABASE PARAMETERS #################

DBName=$DB_PATH

############ PROXY SPECIFIC PARAMETERS #################

ProxyLocalBuffer=24
ProxyOfflineBuffer=72
ProxyConfigFrequency=10
DataSenderFrequency=1

############ PERFORMANCE TUNING #################

StartPollers=5
StartPollersUnreachable=1
StartTrappers=5
StartPingers=1
StartDiscoverers=3
StartHTTPPollers=1

CacheSize=32M
StartDBSyncers=4
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
LogSlowQueries=3000

SocketDir=/var/run/zabbix
EnableRemoteCommands=0
LogRemoteCommands=0
EOF

# CRITICAL FIX: Correct config file permissions!
chown root:zabbix /etc/zabbix/zabbix_proxy.conf
chmod 640 /etc/zabbix/zabbix_proxy.conf

log_success "Configuration file created"

#================================================================
# 7. Create log file
#================================================================
log_info "Creating log file..."

touch /var/log/zabbix/zabbix_proxy.log
chown zabbix:zabbix /var/log/zabbix/zabbix_proxy.log
chmod 644 /var/log/zabbix/zabbix_proxy.log

log_success "Log file created"

#================================================================
# 8. Configure systemd
#================================================================
log_info "Configuring systemd service..."

systemctl daemon-reload
systemctl enable zabbix-proxy

log_success "Service configured"

#================================================================
# 9. Start and verify - IMPROVED!
#================================================================
log_info "Starting Zabbix Proxy..."

# Stop if already running
systemctl stop zabbix-proxy 2>/dev/null || true
sleep 2

# Start
systemctl start zabbix-proxy

# Wait for startup
sleep 5

# CRITICAL CHECK: Is service really running?
if systemctl is-active --quiet zabbix-proxy; then
    log_success "Zabbix Proxy started successfully!"
    echo ""
    systemctl status zabbix-proxy --no-pager -l | head -15

    # Additional check - is process running?
    if pgrep -x "zabbix_proxy" > /dev/null; then
        log_success "Process zabbix_proxy found (PID: $(pgrep -x zabbix_proxy))"
    else
        log_warning "Process zabbix_proxy not found!"
    fi

else
    log_error "Zabbix Proxy failed to start!"
    echo ""
    log_info "Last 30 log lines:"
    journalctl -u zabbix-proxy -n 30 --no-pager
    echo ""
    log_info "Proxy log file:"
    tail -20 /var/log/zabbix/zabbix_proxy.log 2>/dev/null || echo "Log file is empty"
    exit 1
fi

#================================================================
# Summary
#================================================================
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  Zabbix Proxy installed successfully!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

echo "Installation details:"
echo "  • Proxy Name: $PROXY_NAME"
echo "  • Zabbix Server: $ZABBIX_SERVER"
echo "  • Database: SQLite ($DB_PATH)"
echo "  • Config: /etc/zabbix/zabbix_proxy.conf"
echo "  • Log: /var/log/zabbix/zabbix_proxy.log"
echo ""

echo "Next steps:"
echo ""
echo "1. Add proxy on Zabbix Server:"
echo "   Administration → Proxies → Create proxy"
echo "   - Proxy name: $PROXY_NAME"
echo "   - Proxy mode: Active"
echo ""
echo "2. Check connection:"
echo "   grep 'sending configuration' /var/log/zabbix/zabbix_proxy.log"
echo ""
echo "3. Monitor:"
echo "   sudo systemctl status zabbix-proxy"
echo "   sudo tail -f /var/log/zabbix/zabbix_proxy.log"
echo ""

exit 0