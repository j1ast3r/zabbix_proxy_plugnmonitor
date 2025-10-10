#!/bin/bash
#================================================================
# Zabbix Proxy Permission Fix Script
# Fixes all permission issues for Zabbix Proxy
#================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Zabbix Proxy Permission Fix${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR]${NC} This script must be run with sudo"
   exit 1
fi

log() { echo -e "${GREEN}[✓]${NC} $1"; }

# Create all directories
echo "Creating directories..."
mkdir -p /var/log/zabbix
mkdir -p /var/lib/zabbix
mkdir -p /var/run/zabbix
mkdir -p /etc/zabbix
log "Directories created"

# Create zabbix user if not exists
if ! id "zabbix" &>/dev/null; then
    useradd --system --group --home /var/lib/zabbix --shell /sbin/nologin zabbix
    log "User zabbix created"
else
    log "User zabbix exists"
fi

# Set directory permissions
echo ""
echo "Setting permissions..."
chown -R zabbix:zabbix /var/log/zabbix
chown -R zabbix:zabbix /var/lib/zabbix
chown -R zabbix:zabbix /var/run/zabbix

chmod 755 /var/log/zabbix
chmod 750 /var/lib/zabbix
chmod 755 /var/run/zabbix
log "Directory permissions set"

# Fix config file if exists
if [ -f /etc/zabbix/zabbix_proxy.conf ]; then
    chown root:zabbix /etc/zabbix/zabbix_proxy.conf
    chmod 640 /etc/zabbix/zabbix_proxy.conf
    log "Config permissions fixed"
fi

# Fix database if exists
if [ -f /var/lib/zabbix/zabbix_proxy.db ]; then
    chown zabbix:zabbix /var/lib/zabbix/zabbix_proxy.db
    chmod 640 /var/lib/zabbix/zabbix_proxy.db
    log "Database permissions fixed"
fi

# Create log file
touch /var/log/zabbix/zabbix_proxy.log
chown zabbix:zabbix /var/log/zabbix/zabbix_proxy.log
chmod 644 /var/log/zabbix/zabbix_proxy.log
log "Log file created"

# Restart service
echo ""
echo "Restarting service..."
systemctl daemon-reload
systemctl restart zabbix-proxy
sleep 3

if systemctl is-active --quiet zabbix-proxy; then
    log "Zabbix Proxy is running"
else
    echo -e "${RED}[ERROR]${NC} Zabbix Proxy failed to start"
    echo ""
    echo "Check logs:"
    echo "  sudo journalctl -u zabbix-proxy -n 20"
    exit 1
fi

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  Permissions fixed successfully!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

exit 0