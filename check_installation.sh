#!/bin/bash
# Plug & Monitor - Installation Verification Script
# Checks all critical components after installation

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

check_ok() { echo -e "${GREEN}[✓]${NC} $1"; }
check_fail() { echo -e "${RED}[✗]${NC} $1"; ((ERRORS++)); }
check_warn() { echo -e "${YELLOW}[!]${NC} $1"; ((WARNINGS++)); }
check_info() { echo -e "${BLUE}[i]${NC} $1"; }

echo "╔═══════════════════════════════════════════════════════╗"
echo "║  Plug & Monitor - Installation Verification          ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   check_warn "Not running as root - some checks may fail"
fi

#================================================================
# 1. Check Directories
#================================================================
echo "1. Checking directories..."

if [ -d /opt/plug-monitor ]; then
    check_ok "Main directory exists: /opt/plug-monitor"
else
    check_fail "Main directory missing: /opt/plug-monitor"
fi

if [ -d /opt/plug-monitor/config ]; then
    check_ok "Config directory exists"
else
    check_fail "Config directory missing"
fi

if [ -d /opt/plug-monitor/data/scans ]; then
    check_ok "Scans directory exists"
else
    check_fail "Scans directory missing"
fi

if [ -d /var/log/zabbix ]; then
    check_ok "Zabbix log directory exists"
    # Check permissions
    if [ -w /var/log/zabbix ]; then
        check_ok "Zabbix log directory is writable"
    else
        check_fail "Zabbix log directory is NOT writable"
    fi
else
    check_fail "Zabbix log directory missing"
fi

if [ -d /var/lib/zabbix ]; then
    check_ok "Zabbix data directory exists"
else
    check_fail "Zabbix data directory missing"
fi

echo ""

#================================================================
# 2. Check Files
#================================================================
echo "2. Checking critical files..."

check_file() {
    local file="$1"
    local name="$2"

    if [ -f "$file" ]; then
        local size=$(stat -c%s "$file" 2>/dev/null || echo "0")
        if [ "$size" -gt 0 ]; then
            check_ok "$name exists ($size bytes)"
        else
            check_fail "$name exists but is EMPTY (0 bytes)!"
        fi
    else
        check_fail "$name is missing: $file"
    fi
}

check_file "/etc/zabbix/zabbix_proxy.conf" "Zabbix Proxy config"
check_file "/opt/plug-monitor/config/config.yml" "Main config"
check_file "/opt/plug-monitor/03_auto_discovery/auto_discovery.py" "Auto-discovery script"
check_file "/opt/plug-monitor/02_network_scanner/network_scanner.py" "Network scanner"
check_file "/opt/plug-monitor/02_network_scanner/web_dashboard.py" "Web dashboard"

echo ""

#================================================================
# 3. Check Database
#================================================================
echo "3. Checking database..."

if [ -f /var/lib/zabbix/zabbix_proxy.db ]; then
    local db_size=$(stat -c%s /var/lib/zabbix/zabbix_proxy.db)
    check_ok "Database exists ($db_size bytes)"

    # Verify it's a valid SQLite database
    if sqlite3 /var/lib/zabbix/zabbix_proxy.db "SELECT COUNT(*) FROM hosts;" &>/dev/null; then
        check_ok "Database is valid and accessible"
    else
        check_fail "Database exists but appears corrupted"
    fi

    # Check permissions
    local db_owner=$(stat -c '%U:%G' /var/lib/zabbix/zabbix_proxy.db)
    if [ "$db_owner" = "zabbix:zabbix" ]; then
        check_ok "Database has correct ownership (zabbix:zabbix)"
    else
        check_fail "Database has wrong ownership: $db_owner (should be zabbix:zabbix)"
    fi
else
    check_fail "Database is missing: /var/lib/zabbix/zabbix_proxy.db"
fi

echo ""

#================================================================
# 4. Check Configuration
#================================================================
echo "4. Checking Zabbix Proxy configuration..."

# Check for removed parameter
if grep -q "HeartbeatFrequency" /etc/zabbix/zabbix_proxy.conf 2>/dev/null; then
    check_fail "Found deprecated parameter 'HeartbeatFrequency' (remove it!)"
else
    check_ok "No deprecated HeartbeatFrequency parameter"
fi

# Check required parameters
if grep -q "^Server=" /etc/zabbix/zabbix_proxy.conf 2>/dev/null; then
    local server=$(grep "^Server=" /etc/zabbix/zabbix_proxy.conf | cut -d'=' -f2)
    check_ok "Server configured: $server"
else
    check_fail "Server parameter not set"
fi

if grep -q "^Hostname=" /etc/zabbix/zabbix_proxy.conf 2>/dev/null; then
    local hostname=$(grep "^Hostname=" /etc/zabbix/zabbix_proxy.conf | cut -d'=' -f2)
    check_ok "Hostname configured: $hostname"
else
    check_fail "Hostname parameter not set"
fi

if grep -q "^DBName=" /etc/zabbix/zabbix_proxy.conf 2>/dev/null; then
    check_ok "Database path configured"
else
    check_fail "DBName parameter not set"
fi

echo ""

#================================================================
# 5. Check Services
#================================================================
echo "5. Checking systemd services..."

check_service() {
    local service="$1"

    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        check_ok "$service is enabled"
    else
        check_fail "$service is NOT enabled"
    fi

    if systemctl is-active --quiet "$service" 2>/dev/null; then
        check_ok "$service is running"
    else
        check_fail "$service is NOT running"
    fi
}

check_service "zabbix-proxy"
check_service "zabbix-autodiscovery"
check_service "zabbix-dashboard"

echo ""

#================================================================
# 6. Check Process
#================================================================
echo "6. Checking running processes..."

if pgrep -x "zabbix_proxy" > /dev/null; then
    local pid=$(pgrep -x "zabbix_proxy")
    check_ok "Zabbix Proxy process running (PID: $pid)"
else
    check_fail "Zabbix Proxy process NOT running"
fi

if pgrep -f "auto_discovery.py" > /dev/null; then
    check_ok "Auto-discovery daemon running"
else
    check_warn "Auto-discovery daemon NOT running"
fi

if pgrep -f "gunicorn.*web_dashboard" > /dev/null; then
    check_ok "Web dashboard running"
else
    check_warn "Web dashboard NOT running"
fi

echo ""

#================================================================
# 7. Check Network
#================================================================
echo "7. Checking network connectivity..."

# Check Zabbix Server connectivity
if [ -f /opt/plug-monitor/config/config.yml ]; then
    local zabbix_server=$(grep "server:" /opt/plug-monitor/config/config.yml | head -1 | awk '{print $2}')

    if [ -n "$zabbix_server" ]; then
        if ping -c 1 -W 2 "$zabbix_server" &>/dev/null; then
            check_ok "Can ping Zabbix Server: $zabbix_server"
        else
            check_warn "Cannot ping Zabbix Server: $zabbix_server"
        fi

        if timeout 3 bash -c "echo >/dev/tcp/$zabbix_server/10051" 2>/dev/null; then
            check_ok "Zabbix Server port 10051 is reachable"
        else
            check_warn "Cannot connect to Zabbix Server port 10051"
        fi
    fi
fi

# Check dashboard port
local dashboard_port=$(grep "port:" /opt/plug-monitor/config/config.yml 2>/dev/null | grep -v "server_port" | awk '{print $2}' | head -1)
dashboard_port=${dashboard_port:-8080}

if netstat -tlnp 2>/dev/null | grep -q ":$dashboard_port "; then
    check_ok "Dashboard listening on port $dashboard_port"
else
    check_warn "Dashboard NOT listening on port $dashboard_port"
fi

echo ""

#================================================================
# 8. Check Python Environment
#================================================================
echo "8. Checking Python environment..."

if [ -d /opt/plug-monitor/venv ]; then
    check_ok "Python virtual environment exists"

    if [ -f /opt/plug-monitor/venv/bin/python ]; then
        local py_version=$(/opt/plug-monitor/venv/bin/python --version 2>&1)
        check_ok "Python: $py_version"
    else
        check_fail "Python binary missing in venv"
    fi

    # Check required packages
    if /opt/plug-monitor/venv/bin/pip list 2>/dev/null | grep -q "Flask"; then
        check_ok "Flask installed"
    else
        check_fail "Flask NOT installed"
    fi

    if /opt/plug-monitor/venv/bin/pip list 2>/dev/null | grep -q "python-nmap"; then
        check_ok "python-nmap installed"
    else
        check_fail "python-nmap NOT installed"
    fi
else
    check_fail "Python virtual environment missing"
fi

echo ""

#================================================================
# 9. Check Logs
#================================================================
echo "9. Checking recent logs for errors..."

if [ -f /var/log/zabbix/zabbix_proxy.log ]; then
    local error_count=$(grep -c "ERROR\|CRITICAL" /var/log/zabbix/zabbix_proxy.log 2>/dev/null || echo "0")
    if [ "$error_count" -eq 0 ]; then
        check_ok "No errors in Zabbix Proxy log"
    else
        check_warn "Found $error_count error(s) in Zabbix Proxy log"
        echo "    Last 3 errors:"
        grep "ERROR\|CRITICAL" /var/log/zabbix/zabbix_proxy.log | tail -3 | sed 's/^/    /'
    fi
fi

# Check systemd logs
local proxy_errors=$(journalctl -u zabbix-proxy -p err --since "10 minutes ago" --no-pager 2>/dev/null | wc -l)
if [ "$proxy_errors" -eq 0 ]; then
    check_ok "No recent systemd errors for zabbix-proxy"
else
    check_warn "Found $proxy_errors error(s) in systemd logs for zabbix-proxy"
fi

echo ""

#================================================================
# Summary
#================================================================
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  Verification Summary                                 ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Installation is complete and working correctly."
    echo ""
    echo "Access dashboard: http://$(hostname -I | awk '{print $1}'):${dashboard_port}"
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ Installation complete with warnings${NC}"
    echo ""
    echo "Warnings: $WARNINGS"
    echo "Some components may need attention, but core functionality works."
else
    echo -e "${RED}✗ Installation has errors${NC}"
    echo ""
    echo "Errors: $ERRORS"
    echo "Warnings: $WARNINGS"
    echo ""
    echo "Please fix the errors above before proceeding."
    echo ""
    echo "Common fixes:"
    echo "  1. Restart services: sudo systemctl restart zabbix-proxy"
    echo "  2. Check logs: sudo journalctl -u zabbix-proxy -n 50"
    echo "  3. Verify config: sudo cat /etc/zabbix/zabbix_proxy.conf"
fi

echo ""
exit $ERRORS