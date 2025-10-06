# 🚀 Plug & Monitor - Automated Zabbix Monitoring Solution

## Overview

**Plug & Monitor** is a commercial turnkey solution for automated deployment of Zabbix 7.0 LTS monitoring infrastructure. Built on Raspberry Pi, it transforms complex monitoring setup from hours of manual work into a plug-and-play experience.

### The Problem We Solve

Traditional Zabbix deployment requires:
- ⏰ Hours of manual configuration for 10+ hosts
- 🔧 Individual agent installation on each computer
- 📋 Manual host registration in Zabbix Server
- 🎯 Template assignment and configuration
- 👥 Specialized IT knowledge

### Our Solution

**Plug & Monitor** automates the entire process:
```
┌─────────────────────────────────────────────────────────────┐
│  PLUG IN → AUTO SCAN → AUTO DISCOVER → START MONITORING    │
│  10 minutes instead of 10 hours                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Key Features

### ✅ Automated Network Discovery
- Intelligent network scanning with nmap
- OS fingerprinting and device type detection
- SNMP device identification
- Real-time discovery updates

### ✅ Zero-Touch Host Registration
- Automatic host creation in Zabbix via API
- Smart template assignment based on device type
- Automatic group organization
- Duplicate prevention

### ✅ Mass Agent Deployment
- **Windows**: PowerShell scripts with WinRM/PsExec
- **Linux**: Ansible playbooks
- **Active Directory**: GPO integration
- PSK encryption with auto-generated keys

### ✅ Web Management Interface
- Modern responsive dashboard on port 8080
- Real-time scan results
- One-click operations
- Status monitoring

---

## 🎚️ Three Automation Levels

### Level 1: Basic Automation (No Agents)
**Target**: Small business, home users  
**Setup Time**: 10-15 minutes  
**Monitoring**:
- ICMP ping availability
- SNMP metrics for network devices
- Basic uptime tracking
- Auto-template assignment

**Limitations**: No detailed metrics (CPU, RAM, disk)

---

### Level 2: Semi-Automation (With Agents)
**Target**: Medium business, IT departments  
**Setup Time**: 30-60 minutes for 50 hosts  
**Monitoring**:
- Everything from Level 1 +
- Detailed CPU, RAM, disk metrics
- Process monitoring
- Active agent mode with auto-registration
- PSK encryption

**Process**:
1. RPi scans network and adds hosts
2. Admin runs mass deployment script
3. Agents auto-install and register
4. Monitoring starts automatically

---

### Level 3: Full Automation (Enterprise)
**Target**: Large companies, Enterprise  
**Setup Time**: "Plug and forget"  
**Monitoring**:
- Everything from Level 2 +
- Active Directory integration
- GPO agent deployment
- Dynamic template assignment by host role
- Webhook integrations (Telegram, Slack, MS Teams)
- Auto-healing capabilities

**Process**: Complete hands-off deployment via AD and GPO

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     ZABBIX SERVER (Cloud/On-Prem)               │
│                  - PostgreSQL/MySQL Database                     │
│                  - Web Interface                                 │
│                  - API for Automation                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ Secure Connection
                         │
┌────────────────────────▼────────────────────────────────────────┐
│              RASPBERRY PI "AUTO-PROXY" (Your Product)           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  🔍 Network Scanner      - nmap discovery                │  │
│  │  🤖 Auto-Discovery       - Zabbix API integration        │  │
│  │  📊 Web Dashboard        - Flask on port 8080            │  │
│  │  🔌 Zabbix Proxy         - Data collector (SQLite)       │  │
│  │  ⚙️  Systemd Services     - Auto-start daemons           │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┬──────────────┐
         │               │               │              │
    ┌────▼───┐      ┌───▼────┐     ┌───▼────┐    ┌────▼─────┐
    │Windows │      │ Linux  │     │Network │    │   IoT    │
    │Servers │      │Servers │     │Devices │    │ Devices  │
    │+ Agent │      │+ Agent │     │ SNMP   │    │   SNMP   │
    └────────┘      └────────┘     └────────┘    └──────────┘
```

---

## 💻 System Requirements

### Raspberry Pi Requirements
- **Model**: Raspberry Pi 4 (4GB RAM minimum, 8GB recommended)
- **Storage**: 32GB+ microSD card (Class 10 or better)
- **OS**: Raspberry Pi OS (Debian 12) or Ubuntu Server 22.04+
- **Network**: Ethernet connection (WiFi possible but not recommended)
- **Power**: Official Raspberry Pi power supply (5V 3A)

### Zabbix Server Requirements
- **Version**: Zabbix Server 7.0 LTS
- **Database**: PostgreSQL 12+ or MySQL 8.0+
- **Resources**: 2+ CPU cores, 4GB+ RAM
- **OS**: Linux (Ubuntu 22.04/24.04, Debian 12, RHEL 8+, CentOS Stream)
- **Network**: Static IP or FQDN accessible from RPi

### Network Requirements
- **Connectivity**: RPi and Zabbix Server must communicate
- **Ports**: 
  - 10051 (Zabbix Server → Proxy)
  - 10050 (Agents → Proxy)
  - 8080 (Web Dashboard)
  - 161 (SNMP, optional)
- **Permissions**: Network scanning capabilities (may require admin approval)

---

## ⚡ Quick Start

### Option 1: Master Installer (Recommended)
```bash
# Download and run the master installer
wget https://your-domain.com/plug-monitor/master_install.sh
chmod +x master_install.sh
sudo ./master_install.sh
```

The installer will:
1. ✅ Check system requirements
2. ✅ Install Zabbix Proxy
3. ✅ Deploy network scanner
4. ✅ Setup auto-discovery daemon
5. ✅ Launch web dashboard
6. ✅ Configure systemd services

### Option 2: Manual Installation
See [INSTALLATION.md](docs/INSTALLATION.md) for step-by-step manual setup.

---

## 📖 Documentation Structure

```
docs/
├── INSTALLATION.md       - Detailed installation guide
├── CONFIGURATION.md      - Configuration and tuning
├── BUSINESS_MODEL.md     - Monetization strategies
├── TROUBLESHOOTING.md    - Common issues and fixes
├── API_REFERENCE.md      - Zabbix API usage examples
└── UPGRADE_GUIDE.md      - Version upgrade procedures
```

---

## 🔧 Configuration

### Initial Setup Wizard
After installation, access the web dashboard:
```
http://<raspberry-pi-ip>:8080
```

Follow the setup wizard:
1. **Zabbix Server Connection**: Enter server URL and credentials
2. **Network Settings**: Define scan range (e.g., 192.168.1.0/24)
3. **Discovery Rules**: Configure what to monitor
4. **Templates**: Select default templates for auto-assignment
5. **Launch**: Start automated monitoring

### Configuration Files
```
/etc/zabbix/zabbix_proxy.conf          - Zabbix Proxy config
/opt/plug-monitor/config/config.yml    - Main application config
/opt/plug-monitor/config/discovery.yml - Discovery rules
/opt/plug-monitor/config/templates.yml - Template mappings
```

---

## 🎯 Usage Examples

### Scenario 1: Small Office Network (Level 1)
```bash
# 1. Connect RPi to network
# 2. Access dashboard: http://192.168.1.100:8080
# 3. Click "Start Auto Discovery"
# 4. Watch as devices appear in Zabbix
# Total time: 10 minutes
```

### Scenario 2: 50 Workstations with Agents (Level 2)
```bash
# 1. Auto-discovery adds all hosts
# 2. Export discovered hosts list
# 3. Run mass deployment:
cd /opt/plug-monitor/04_windows_deployment
./deploy_agent_windows.ps1 -HostList discovered_hosts.txt
# 4. Agents install and register automatically
# Total time: 45 minutes
```

### Scenario 3: Enterprise with AD (Level 3)
```bash
# 1. Configure AD integration in config.yml
# 2. Enable AD sync service
# 3. Deploy GPO for automatic agent installation
# 4. System manages itself
# Total time: Initial setup 2 hours, then zero maintenance
```

---

## 🔐 Security

### Built-in Security Features
- ✅ PSK encryption for all agent communications
- ✅ Automatic unique PSK key generation per host
- ✅ API credentials stored encrypted
- ✅ Minimum required privileges principle
- ✅ Systemd security hardening
- ✅ Firewall rules included in documentation

### Security Best Practices
```bash
# 1. Change default passwords immediately
# 2. Use SSH key authentication for RPi
# 3. Enable UFW firewall
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 8080/tcp    # Dashboard
sudo ufw allow 10051/tcp   # Zabbix Proxy
sudo ufw enable

# 4. Regular updates
sudo apt update && sudo apt upgrade -y
```

---

## 📊 Monitoring Capabilities

### Basic Metrics (All Levels)
- Device availability (ICMP)
- Response time
- Uptime tracking
- SNMP OID polling

### Advanced Metrics (With Agents)
- **System**: CPU, RAM, Swap, Load average
- **Storage**: Disk space, I/O, inode usage
- **Network**: Interface statistics, bandwidth
- **Processes**: Running processes, zombies
- **Services**: Service status monitoring
- **Logs**: Log file monitoring with keywords

### Templates Included
- Linux by Zabbix agent active
- Windows by Zabbix agent active
- Generic SNMP device
- Network switch (SNMP)
- Router (SNMP)
- Printer (SNMP)
- Custom templates for specific apps

---

## 🌐 Web Dashboard Features

Access at `http://<rpi-ip>:8080`

### Main Dashboard
- 📊 **Overview**: Total hosts, online/offline status
- 🔍 **Discovery**: Real-time scan results
- 📈 **Statistics**: Monitoring coverage
- ⚠️ **Alerts**: Active problems from Zabbix

### Network Scanner Page
- Start/stop network scans
- Configure scan range
- View discovered devices
- Device type classification
- OS detection results

### Host Management
- Bulk host actions
- Template assignment
- Group management
- Quick agent deployment

### System Status
- Proxy status and statistics
- Service health checks
- Log viewer
- Resource usage

---

## 🛠️ Maintenance

### Regular Tasks
```bash
# Check service status
sudo systemctl status zabbix-proxy
sudo systemctl status zabbix-autodiscovery
sudo systemctl status zabbix-dashboard

# View logs
sudo journalctl -u zabbix-proxy -f
sudo tail -f /var/log/zabbix/zabbix_proxy.log

# Database cleanup (automatic, but can trigger manually)
sqlite3 /var/lib/zabbix/zabbix_proxy.db "VACUUM;"

# Update discovery rules
nano /opt/plug-monitor/config/discovery.yml
sudo systemctl restart zabbix-autodiscovery
```

### Backup Recommendations
```bash
# Backup critical data daily
/var/lib/zabbix/                     # Proxy database
/etc/zabbix/                         # Configuration
/opt/plug-monitor/config/            # Application config
/opt/plug-monitor/data/scans/        # Scan history
```

---

## 🐛 Troubleshooting

### Problem: RPi can't connect to Zabbix Server
```bash
# Check connectivity
ping <zabbix-server-ip>
telnet <zabbix-server-ip> 10051

# Check proxy config
grep ^Server= /etc/zabbix/zabbix_proxy.conf

# Check proxy logs
tail -f /var/log/zabbix/zabbix_proxy.log
```

### Problem: Hosts not auto-adding
```bash
# Check auto-discovery service
sudo systemctl status zabbix-autodiscovery

# Check API connectivity
curl -X POST http://<zabbix-server>/api_jsonrpc.php \
  -H "Content-Type: application/json-rpc" \
  -d '{"jsonrpc":"2.0","method":"apiinfo.version","id":1,"params":{}}'

# Check logs
sudo journalctl -u zabbix-autodiscovery -n 50
```

### Problem: Agent deployment fails
```bash
# Windows: Check WinRM
Test-WSMan <target-host>

# Linux: Check SSH
ssh <target-host> echo "Connection OK"

# Check credentials in deployment config
```

For more troubleshooting, see [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

---

## 💼 Business Model & Pricing

### Target Markets

#### 1. Small Business (10-50 devices)
- **Product**: Level 1 - Plug & Play device
- **Price**: $299 one-time
- **Support**: Email support, online documentation

#### 2. Medium Business (50-200 devices)
- **Product**: Level 2 - Device + Agent deployment
- **Price**: $699 one-time + optional $99/year support
- **Support**: Priority email, quarterly updates

#### 3. Enterprise (200+ devices)
- **Product**: Level 3 - Full automation with AD integration
- **Price**: Custom ($2000-5000) or $199/month SaaS
- **Support**: Dedicated support, implementation services

### Revenue Streams
1. **Hardware Sales**: Pre-configured Raspberry Pi devices
2. **Software Licensing**: Download + license key model
3. **SaaS**: Managed cloud Zabbix + RPi proxy
4. **Professional Services**: Implementation, training, custom development
5. **Support Contracts**: Annual support and updates

See [docs/BUSINESS_MODEL.md](docs/BUSINESS_MODEL.md) for detailed business strategy.

---

## 🔄 Upgrade & Updates

### Software Updates
```bash
# Update Plug & Monitor software
cd /opt/plug-monitor
git pull origin main
sudo ./update.sh

# Update Zabbix Proxy
sudo apt update
sudo apt upgrade zabbix-proxy-sqlite3
```

### Version Compatibility
- Zabbix Server 7.0 LTS ↔️ Plug & Monitor 1.x
- Zabbix Server 6.4 LTS ↔️ Plug & Monitor 1.x (limited)
- Older Zabbix versions: Not recommended

---

## 🤝 Support & Community

### Getting Help
- 📧 **Email**: 
- 📖 **Docs**: 
- 🐛 **Bug Reports**: GitHub Issues

### Commercial Support
- **Basic**: Email support, 48h response
- **Professional**: Priority support, 24h response, quarterly reviews
- **Enterprise**: Dedicated support engineer, 4h response, on-site available

---

## 📜 License

**Proprietary Commercial License**

This software is commercial and requires a valid license for production use.

- ✅ 30-day trial: Full features, no license required
- ✅ Development use: Free for testing/development
- ❌ Production use: Requires paid license

Contact sales@plug-monitor.com for licensing.

---

## 🙏 Acknowledgments

Built with excellent open-source technologies:
- **Zabbix**: Industry-leading monitoring platform
- **Raspberry Pi**: Affordable, reliable hardware
- **Python/Flask**: Web framework and automation
- **nmap**: Network scanning
- **Ansible**: Configuration management

---

## 📞 Contact

**Plug & Monitor Team**
- Website: https://rautenbach.it
- Support: support@rautenbach.it info@rautenbach.it
- Phone: 

---

## 🚀 Get Started Now!

```bash
# Download and run the installer
wget https://plug-monitor.com/install
chmod +x install
sudo ./install

# Or use the step-by-step guide
cat docs/INSTALLATION.md
```

**Transform your monitoring deployment from hours to minutes!**

---

*Last updated: October 2025*  
*Version: 1.0.0*