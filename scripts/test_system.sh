#!/bin/bash
#================================================================
# Plug & Monitor - System Test Script
# Comprehensive testing of all components
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
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNINGS=0

# Paths
INSTALL_DIR="/opt/plug-monitor"
CONFIG_FILE="$INSTALL_DIR/config/config.yml"

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Plug & Monitor - System Test Suite          ║${NC}"
echo -e "${BLUE}║   Version 1.0.1                                ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
echo ""

#================================================================
# Test 1: Installation Check
#================================================================
echo -e "${BLUE}[TEST 1]${NC} Installation Check"
echo "─────────────────────────────────────────────────"

if [ -d "$INSTALL_DIR" ]; then
    log_success "Installation directory exists: $INSTALL_DIR"
    ((TESTS_PASSED++))
else
    log_error "Installation directory not found: $INSTALL_DIR"
    ((TESTS_FAILED++))
    exit 1
fi

# Check directory structure
REQUIRED_DIRS=(
    "config"
    "data/scans"
    "02_network_scanner"
    "03_auto_discovery"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$INSTALL_DIR/$dir" ]; then
        log_success "Directory exists: $dir"
        ((TESTS_PASSED++))
    else
        log_error "Directory missing: $dir"
        ((TESTS_FAILED++))
    fi
done

echo ""

#================================================================
# Test 2: Configuration File
#================================================================
echo -e "${BLUE}[TEST 2]${NC} Configuration File"
echo "─────────────────────────────────────────────────"

if [ -f "$CONFIG_FILE" ]; then
    log_success "Config file exists"
    ((TESTS_PASSED++))

    # Check for critical settings
    if grep -q "zabbix:" "$CONFIG_FILE"; then
        log_success "Zabbix section found"
        ((TESTS_PASSED++))
    else
        log_error "Zabbix section missing"
        ((TESTS_FAILED++))
    fi

    if grep -q "network:" "$CONFIG_FILE"; then
        log_success "Network section found"
        ((TESTS_PASSED++))
    else
        log_error "Network section missing"
        ((TESTS_FAILED++))
    fi

    if grep -q "discovery:" "$CONFIG_FILE"; then
        log_success "Discovery section found"
        ((TESTS_PASSED++))
    else
        log_error "Discovery section missing"
        ((TESTS_FAILED++))
    fi

    # Check template names (CRITICAL!)
    if grep -q "Linux by Zabbix agent active" "$CONFIG_FILE"; then
        log_success "Linux template name correct (Zabbix 7.0)"
        ((TESTS_PASSED++))
    else
        log_warning "Linux template name may be incorrect"
        ((TESTS_WARNINGS++))
    fi

    if grep -q "Windows by Zabbix agent active" "$CONFIG_FILE"; then
        log_success "Windows template name correct (Zabbix 7.0)"
        ((TESTS_PASSED++))
    else
        log_warning "Windows template name may be incorrect"
        ((TESTS_WARNINGS++))
    fi
else
    log_error "Config file not found: $CONFIG_FILE"
    ((TESTS_FAILED++))
fi

echo ""

#================================================================
# Test 3: Python Files
#================================================================
echo -e "${BLUE}[TEST 3]${NC} Python Files"
echo "─────────────────────────────────────────────────"

REQUIRED_FILES=(
    "02_network_scanner/network_scanner.py"
    "02_network_scanner/web_dashboard.py"
    "03_auto_discovery/auto_discovery.py"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$INSTALL_DIR/$file" ]; then
        SIZE=$(stat -c%s "$INSTALL_DIR/$file")
        if [ $SIZE -gt 0 ]; then
            log_success "$file exists ($SIZE bytes)"
            ((TESTS_PASSED++))
        else
            log_error "$file is empty (0 bytes)!"
            ((TESTS_FAILED++))
        fi
    else
        log_error "$file not found"
        ((TESTS_FAILED++))
    fi
done

# Check for templates directory
if [ -d "$INSTALL_DIR/02_network_scanner/templates" ]; then
    log_success "Templates directory exists"
    ((TESTS_PASSED++))

    if [ -f "$INSTALL_DIR/02_network_scanner/templates/dashboard.html" ]; then
        log_success "dashboard.html in templates/"
        ((TESTS_PASSED++))
    else
        log_error "dashboard.html not found in templates/"
        ((TESTS_FAILED++))
    fi
else
    log_error "Templates directory missing"
    ((TESTS_FAILED++))
fi

# Check template names in auto_discovery.py
AUTO_DISCOVERY_FILE="$INSTALL_DIR/03_auto_discovery/auto_discovery.py"
if [ -f "$AUTO_DISCOVERY_FILE" ]; then
    if grep -q "Linux by Zabbix agent active" "$AUTO_DISCOVERY_FILE"; then
        log_success "auto_discovery.py: Linux template correct"
        ((TESTS_PASSED++))
    else
        log_error "auto_discovery.py: Linux template incorrect"
        ((TESTS_FAILED++))
    fi

    if grep -q "Windows by Zabbix agent active" "$AUTO_DISCOVERY_FILE"; then
        log_success "auto_discovery.py: Windows template correct"
        ((TESTS_PASSED++))
    else
        log_error "auto_discovery.py: Windows template incorrect"
        ((TESTS_FAILED++))
    fi

    if grep -q "Generic SNMP" "$AUTO_DISCOVERY_FILE"; then
        log_success "auto_discovery.py: Network template correct"
        ((TESTS_PASSED++))
    else
        log_error "auto_discovery.py: Network template incorrect"
        ((TESTS_FAILED++))
    fi
fi

echo ""

#================================================================
# Test 4: Systemd Services
#================================================================
echo -e "${BLUE}[TEST 4]${NC} Systemd Services"
echo "─────────────────────────────────────────────────"

SERVICES=(
    "zabbix-proxy"
    "zabbix-autodiscovery"
    "zabbix-dashboard"
)

for service in "${SERVICES[@]}"; do
    if systemctl list-unit-files | grep -q "$service.service"; then
        log_success "$service.service exists"
        ((TESTS_PASSED++))

        if systemctl is-enabled --quiet "$service"; then
            log_success "$service is enabled"
            ((TESTS_PASSED++))
        else
            log_warning "$service is not enabled"
            ((TESTS_WARNINGS++))
        fi

        if systemctl is-active --quiet "$service"; then
            log_success "$service is running"
            ((TESTS_PASSED++))
        else
            log_error "$service is not running"
            ((TESTS_FAILED++))
        fi
    else
        log_error "$service.service not found"
        ((TESTS_FAILED++))
    fi
done

echo ""

#================================================================
# Test 5: Zabbix Proxy
#================================================================
echo -e "${BLUE}[TEST 5]${NC} Zabbix Proxy"
echo "─────────────────────────────────────────────────"

# Check Zabbix user
if id "zabbix" &>/dev/null; then
    log_success "Zabbix user exists"
    ((TESTS_PASSED++))
else
    log_error "Zabbix user not found"
    ((TESTS_FAILED++))
fi

# Check database
DB_PATH="/var/lib/zabbix/zabbix_proxy.db"
if [ -f "$DB_PATH" ]; then
    SIZE=$(stat -c%s "$DB_PATH")
    log_success "Database exists ($SIZE bytes)"
    ((TESTS_PASSED++))

    # Check permissions
    OWNER=$(stat -c '%U:%G' "$DB_PATH")
    if [ "$OWNER" = "zabbix:zabbix" ]; then
        log_success "Database permissions correct"
        ((TESTS_PASSED++))
    else
        log_error "Database permissions wrong (owner: $OWNER)"
        ((TESTS_FAILED++))
    fi
else
    log_error "Database not found: $DB_PATH"
    ((TESTS_FAILED++))
fi

# Check log file
LOG_FILE="/var/log/zabbix/zabbix_proxy.log"
if [ -f "$LOG_FILE" ]; then
    log_success "Log file exists"
    ((TESTS_PASSED++))

    # Check for recent activity
    if [ -n "$(find "$LOG_FILE" -mmin -5)" ]; then
        log_success "Log file recently modified (proxy active)"
        ((TESTS_PASSED++))
    else
        log_warning "Log file not recently modified"
        ((TESTS_WARNINGS++))
    fi

    # Check for errors
    if tail -100 "$LOG_FILE" | grep -qi "error\|failed\|cannot"; then
        log_warning "Recent errors found in log"
        ((TESTS_WARNINGS++))
    else
        log_success "No recent errors in log"
        ((TESTS_PASSED++))
    fi
else
    log_error "Log file not found: $LOG_FILE"
    ((TESTS_FAILED++))
fi

echo ""

#================================================================
# Test 6: Network Connectivity
#================================================================
echo -e "${BLUE}[TEST 6]${NC} Network Connectivity"
echo "─────────────────────────────────────────────────"

# Check if config has Zabbix server
if [ -f "$CONFIG_FILE" ]; then
    ZABBIX_SERVER=$(grep "server:" "$CONFIG_FILE" | head -1 | awk '{print $2}')

    if [ -n "$ZABBIX_SERVER" ]; then
        log_info "Testing connection to Zabbix Server: $ZABBIX_SERVER"

        # Ping test
        if ping -c 1 -W 2 "$ZABBIX_SERVER" &>/dev/null; then
            log_success "Ping to $ZABBIX_SERVER successful"
            ((TESTS_PASSED++))
        else
            log_error "Cannot ping $ZABBIX_SERVER"
            ((TESTS_FAILED++))
        fi

        # Port 10051 test
        if timeout 2 bash -c "echo > /dev/tcp/$ZABBIX_SERVER/10051" 2>/dev/null; then
            log_success "Port 10051 on $ZABBIX_SERVER is open"
            ((TESTS_PASSED++))
        else
            log_error "Port 10051 on $ZABBIX_SERVER is closed"
            ((TESTS_FAILED++))
        fi
    fi
fi

# Dashboard port
if netstat -tlnp 2>/dev/null | grep -q ":8080"; then
    log_success "Dashboard listening on port 8080"
    ((TESTS_PASSED++))
else
    log_error "Dashboard not listening on port 8080"
    ((TESTS_FAILED++))
fi

echo ""

#================================================================
# Test 7: Python Environment
#================================================================
echo -e "${BLUE}[TEST 7]${NC} Python Environment"
echo "─────────────────────────────────────────────────"

if [ -d "$INSTALL_DIR/venv" ]; then
    log_success "Virtual environment exists"
    ((TESTS_PASSED++))

    # Check Python packages
    VENV_PYTHON="$INSTALL_DIR/venv/bin/python"
    if [ -f "$VENV_PYTHON" ]; then
        log_success "Python executable found"
        ((TESTS_PASSED++))

        # Check critical packages
        REQUIRED_PACKAGES=("flask" "pyyaml" "requests" "python-nmap")

        for package in "${REQUIRED_PACKAGES[@]}"; do
            if "$VENV_PYTHON" -c "import ${package//-/_}" 2>/dev/null; then
                log_success "Package installed: $package"
                ((TESTS_PASSED++))
            else
                log_error "Package missing: $package"
                ((TESTS_FAILED++))
            fi
        done
    fi
else
    log_error "Virtual environment not found"
    ((TESTS_FAILED++))
fi

echo ""

#================================================================
# Test 8: Permissions
#================================================================
echo -e "${BLUE}[TEST 8]${NC} File Permissions"
echo "─────────────────────────────────────────────────"

# Zabbix directories
ZABBIX_DIRS=(
    "/var/log/zabbix"
    "/var/lib/zabbix"
    "/var/run/zabbix"
    "/etc/zabbix"
)

for dir in "${ZABBIX_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        OWNER=$(stat -c '%U:%G' "$dir")
        if [ "$OWNER" = "zabbix:zabbix" ]; then
            log_success "$dir owner correct (zabbix:zabbix)"
            ((TESTS_PASSED++))
        else
            log_error "$dir owner wrong ($OWNER)"
            ((TESTS_FAILED++))
        fi
    else
        log_error "$dir not found"
        ((TESTS_FAILED++))
    fi
done

# Config file permissions
if [ -f "$CONFIG_FILE" ]; then
    PERMS=$(stat -c '%a' "$CONFIG_FILE")
    if [ "$PERMS" = "600" ] || [ "$PERMS" = "640" ]; then
        log_success "Config file permissions secure ($PERMS)"
        ((TESTS_PASSED++))
    else
        log_warning "Config file permissions too open ($PERMS)"
        ((TESTS_WARNINGS++))
    fi
fi

echo ""

#================================================================
# Summary
#================================================================
TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED + TESTS_WARNINGS))

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                TEST SUMMARY                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Total tests run:     $TOTAL_TESTS"
echo -e "${GREEN}Passed:              $TESTS_PASSED${NC}"
echo -e "${RED}Failed:              $TESTS_FAILED${NC}"
echo -e "${YELLOW}Warnings:            $TESTS_WARNINGS${NC}"
echo ""

# Overall status
if [ $TESTS_FAILED -eq 0 ]; then
    if [ $TESTS_WARNINGS -eq 0 ]; then
        echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
        echo ""
        echo "System is fully operational."
        exit 0
    else
        echo -e "${YELLOW}⚠ TESTS PASSED WITH WARNINGS${NC}"
        echo ""
        echo "System is operational but has minor issues."
        echo "Check warnings above for details."
        exit 0
    fi
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    echo "System has critical issues that need attention:"
    echo ""
    echo "1. Review failed tests above"
    echo "2. Check service logs:"
    echo "   sudo journalctl -u zabbix-proxy -n 50"
    echo "   sudo journalctl -u zabbix-autodiscovery -n 50"
    echo "   sudo journalctl -u zabbix-dashboard -n 50"
    echo ""
    echo "3. Try applying fixes:"
    echo "   sudo bash apply_fixes.sh"
    echo ""
    exit 1
fi