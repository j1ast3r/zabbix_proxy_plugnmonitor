#!/bin/bash
#================================================================
# Plug & Monitor - Critical Fixes Apply Script
# Автоматически применяет исправления к установленной системе
# Version: 1.0.1
#================================================================

set -e

# Colors
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

# Paths
INSTALL_DIR="/opt/plug-monitor"
BACKUP_DIR="/opt/plug-monitor/backups/$(date +%Y%m%d_%H%M%S)"

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Plug & Monitor - Apply Critical Fixes${NC}"
echo -e "${BLUE}  Version 1.0.1${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Check if installed
if [ ! -d "$INSTALL_DIR" ]; then
    log_error "Plug & Monitor not found in $INSTALL_DIR"
    log_error "Please run master_install.sh first"
    exit 1
fi

log_info "Found Plug & Monitor installation"
echo ""

# Create backup
log_info "Creating backup..."
mkdir -p "$BACKUP_DIR"
cp -r "$INSTALL_DIR/03_auto_discovery/auto_discovery.py" "$BACKUP_DIR/" 2>/dev/null || true
cp -r "$INSTALL_DIR/config/config.yml" "$BACKUP_DIR/" 2>/dev/null || true
cp -r "$INSTALL_DIR/02_network_scanner/" "$BACKUP_DIR/" 2>/dev/null || true
log_success "Backup created: $BACKUP_DIR"
echo ""

#================================================================
# Fix 1: Update auto_discovery.py template names
#================================================================
log_info "Fix 1: Updating template names in auto_discovery.py..."

AUTO_DISCOVERY_FILE="$INSTALL_DIR/03_auto_discovery/auto_discovery.py"

if [ ! -f "$AUTO_DISCOVERY_FILE" ]; then
    log_error "File not found: $AUTO_DISCOVERY_FILE"
    exit 1
fi

# Convert line endings
sed -i 's/\r$//' "$AUTO_DISCOVERY_FILE"

# Replace template names
sed -i "s/\['Template OS Linux'\]/['Linux by Zabbix agent active']/g" "$AUTO_DISCOVERY_FILE"
sed -i "s/\['Template OS Windows'\]/['Windows by Zabbix agent active']/g" "$AUTO_DISCOVERY_FILE"
sed -i "s/\['Template Net Network Generic Device SNMPv2'\]/['Generic SNMP']/g" "$AUTO_DISCOVERY_FILE"
sed -i "s/\['Template Module Generic SNMPv2'\]/['Generic SNMP']/g" "$AUTO_DISCOVERY_FILE"
sed -i "s/\['Template Module ICMP Ping'\]/['ICMP Ping']/g" "$AUTO_DISCOVERY_FILE"

log_success "Template names updated in auto_discovery.py"
echo ""

#================================================================
# Fix 2: Create templates directory for Flask
#================================================================
log_info "Fix 2: Creating templates directory structure..."

TEMPLATES_DIR="$INSTALL_DIR/02_network_scanner/templates"
mkdir -p "$TEMPLATES_DIR"

# Find dashboard.html
DASHBOARD_HTML=""
if [ -f "$INSTALL_DIR/dashboard.html" ]; then
    DASHBOARD_HTML="$INSTALL_DIR/dashboard.html"
elif [ -f "$INSTALL_DIR/02_network_scanner/dashboard.html" ]; then
    DASHBOARD_HTML="$INSTALL_DIR/02_network_scanner/dashboard.html"
else
    log_warning "dashboard.html not found, skipping..."
fi

if [ -n "$DASHBOARD_HTML" ]; then
    cp "$DASHBOARD_HTML" "$TEMPLATES_DIR/dashboard.html"
    log_success "dashboard.html copied to templates/"
fi

log_success "Templates directory created"
echo ""

#================================================================
# Fix 3: Update config.yml template_mapping
#================================================================
log_info "Fix 3: Updating config.yml template_mapping..."

CONFIG_FILE="$INSTALL_DIR/config/config.yml"

if [ -f "$CONFIG_FILE" ]; then
    # Update template names in config
    sed -i 's/"Template OS Linux"/"Linux by Zabbix agent active"/g' "$CONFIG_FILE"
    sed -i 's/"Template OS Windows"/"Windows by Zabbix agent active"/g' "$CONFIG_FILE"
    sed -i 's/"Template Net Network Generic Device SNMPv2"/"Generic SNMP"/g' "$CONFIG_FILE"
    sed -i 's/"Template Module Generic SNMPv2"/"Generic SNMP"/g' "$CONFIG_FILE"
    sed -i 's/"Template Module ICMP Ping"/"ICMP Ping"/g' "$CONFIG_FILE"

    log_success "config.yml updated"
else
    log_warning "config.yml not found, will be created on next restart"
fi

echo ""

#================================================================
# Fix 4: Convert all Python files to Unix line endings
#================================================================
log_info "Fix 4: Converting Python files to Unix format..."

find "$INSTALL_DIR" -name "*.py" -type f -exec sed -i 's/\r$//' {} \;

log_success "All Python files converted to Unix format"
echo ""

#================================================================
# Fix 5: Set correct permissions
#================================================================
log_info "Fix 5: Setting correct permissions..."

chmod +x "$AUTO_DISCOVERY_FILE" 2>/dev/null || true
chown -R root:root "$INSTALL_DIR/02_network_scanner" 2>/dev/null || true
chown -R root:root "$INSTALL_DIR/03_auto_discovery" 2>/dev/null || true
chmod 600 "$CONFIG_FILE" 2>/dev/null || true

log_success "Permissions set"
echo ""

#================================================================
# Restart services
#================================================================
log_info "Restarting services..."

systemctl daemon-reload

# Restart auto-discovery
if systemctl is-active --quiet zabbix-autodiscovery; then
    systemctl restart zabbix-autodiscovery
    log_success "zabbix-autodiscovery restarted"
else
    log_warning "zabbix-autodiscovery not running, starting..."
    systemctl start zabbix-autodiscovery || log_warning "Failed to start zabbix-autodiscovery"
fi

# Restart dashboard
if systemctl is-active --quiet zabbix-dashboard; then
    systemctl restart zabbix-dashboard
    log_success "zabbix-dashboard restarted"
else
    log_warning "zabbix-dashboard not running, starting..."
    systemctl start zabbix-dashboard || log_warning "Failed to start zabbix-dashboard"
fi

echo ""

#================================================================
# Verify fixes
#================================================================
log_info "Verifying fixes..."
echo ""

# Check template names in auto_discovery.py
log_info "Checking template names..."
if grep -q "Linux by Zabbix agent active" "$AUTO_DISCOVERY_FILE"; then
    log_success "✅ Linux template name correct"
else
    log_error "❌ Linux template name not updated"
fi

if grep -q "Windows by Zabbix agent active" "$AUTO_DISCOVERY_FILE"; then
    log_success "✅ Windows template name correct"
else
    log_error "❌ Windows template name not updated"
fi

if grep -q "Generic SNMP" "$AUTO_DISCOVERY_FILE"; then
    log_success "✅ Network template name correct"
else
    log_error "❌ Network template name not updated"
fi

if grep -q "ICMP Ping" "$AUTO_DISCOVERY_FILE"; then
    log_success "✅ ICMP template name correct"
else
    log_error "❌ ICMP template name not updated"
fi

echo ""

# Check templates directory
if [ -d "$TEMPLATES_DIR" ]; then
    log_success "✅ Templates directory exists"

    if [ -f "$TEMPLATES_DIR/dashboard.html" ]; then
        log_success "✅ dashboard.html in templates/"
    else
        log_warning "⚠️  dashboard.html not found in templates/"
    fi
else
    log_error "❌ Templates directory not created"
fi

echo ""

# Check services
log_info "Checking services..."

if systemctl is-active --quiet zabbix-autodiscovery; then
    log_success "✅ zabbix-autodiscovery running"
else
    log_error "❌ zabbix-autodiscovery not running"
    log_info "Check logs: sudo journalctl -u zabbix-autodiscovery -n 50"
fi

if systemctl is-active --quiet zabbix-dashboard; then
    log_success "✅ zabbix-dashboard running"
else
    log_error "❌ zabbix-dashboard not running"
    log_info "Check logs: sudo journalctl -u zabbix-dashboard -n 50"
fi

echo ""

#================================================================
# Summary
#================================================================
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  Fixes Applied Successfully!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

echo "Applied fixes:"
echo "  ✅ Template names updated to Zabbix 7.0 format"
echo "  ✅ Templates directory structure created"
echo "  ✅ Config file updated"
echo "  ✅ Python files converted to Unix format"
echo "  ✅ Permissions set correctly"
echo "  ✅ Services restarted"
echo ""

echo "Backup location: $BACKUP_DIR"
echo ""

echo "Next steps:"
echo "  1. Test auto-discovery:"
echo "     sudo journalctl -u zabbix-autodiscovery -f"
echo ""
echo "  2. Access dashboard:"
echo "     http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "  3. Run network scan and check if templates apply correctly"
echo ""
echo "  4. If issues persist, check:"
echo "     - Zabbix version (must be 7.0.x)"
echo "     - Template names in Zabbix Server"
echo "     - API connectivity"
echo ""

log_info "Fix script completed!"