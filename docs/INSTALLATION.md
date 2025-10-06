# Installation Guide - Plug & Monitor

## Prerequisites

### Hardware
- Raspberry Pi 4 (4GB RAM minimum, 8GB recommended)
- 32GB+ microSD card (Class 10+)
- Stable power supply (5V 3A)
- Ethernet connection

### Software
- Raspberry Pi OS (Debian 12) or Ubuntu Server 22.04+
- Zabbix Server 7.0 LTS already installed and accessible

### Network
- Static IP or DHCP reservation for RPi
- Network access to Zabbix Server
- Ability to scan target network

## Method 1: Automated Installation (Recommended)

### Step 1: Download Installer
```bash
wget https://plug-monitor.com/install/master_install.sh
chmod +x master_install.sh
```

### Step 2: Run Installer
```bash
sudo ./master_install.sh
```

### Step 3: Configuration Wizard
Answer prompts:
- Zabbix Server IP
- API credentials
- Network range to scan
- Dashboard port (default: 8080)
- Admin password

Installation takes 10-15 minutes.

### Step 4: Verify
```bash
# Check services
sudo systemctl status zabbix-proxy
sudo systemctl status zabbix-autodiscovery
sudo systemctl status zabbix-dashboard

# Access dashboard
http://<rpi-ip>:8080
```

## Method 2: Manual Installation

### 1. System Preparation
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y wget curl git python3 python3-pip \
    python3-venv nmap sqlite3 ufw openssl jq
```

### 2. Install Zabbix Proxy
```bash
cd /opt
git clone https://github.com/your-repo/plug-monitor.git
cd plug-monitor/01_raspberry_pi

sudo ./install_zabbix_proxy.sh
```

Enter when prompted:
- Zabbix Server IP: `192.168.1.10`
- Proxy name: `PlugMonitor-Proxy-RPI001`

### 3. Create Directory Structure
```bash
sudo mkdir -p /opt/plug-monitor/{config,data/scans,data/keys}
sudo mkdir -p /var/log/plug-monitor
```

### 4. Setup Python Environment
```bash
cd /opt/plug-monitor
python3 -m venv venv
source venv/bin/activate
pip install -r 02_network_scanner/requirements.txt
deactivate
```

### 5. Configure Application
```bash
sudo cp config.yml.example /opt/plug-monitor/config/config.yml
sudo nano /opt/plug-monitor/config/config.yml
```

Edit values:
```yaml
zabbix:
  server: 192.168.1.10
  api_url: http://192.168.1.10/api_jsonrpc.php
  api_user: Admin
  api_password: your-password
  proxy_name: PlugMonitor-Proxy-RPI001

network:
  scan_range: 192.168.1.0/24
```

### 6. Install Services
```bash
# Auto-discovery service
sudo cp 03_auto_discovery/systemd/zabbix-autodiscovery.service \
    /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zabbix-autodiscovery
sudo systemctl start zabbix-autodiscovery

# Dashboard service
sudo tee /etc/systemd/system/zabbix-dashboard.service > /dev/null <<EOF
[Unit]
Description=Plug & Monitor Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/plug-monitor/02_network_scanner
ExecStart=/opt/plug-monitor/venv/bin/gunicorn -w 2 -b 0.0.0.0:8080 web_dashboard:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable zabbix-dashboard
sudo systemctl start zabbix-dashboard
```

### 7. Configure Firewall
```bash
sudo ufw allow 22/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 10050/tcp
sudo ufw allow 10051/tcp
sudo ufw enable
```

### 8. Add Proxy in Zabbix Web
1. Login to Zabbix web interface
2. Go to **Administration → Proxies**
3. Click **Create proxy**
4. Enter:
   - Name: `PlugMonitor-Proxy-RPI001`
   - Mode: Active
5. Click **Add**

Wait 1-2 minutes for proxy to connect.

## Post-Installation

### Verify Installation
```bash
# Check proxy connection
sudo tail -f /var/log/zabbix/zabbix_proxy.log

# Test network scanner
cd /opt/plug-monitor/02_network_scanner
../venv/bin/python network_scanner.py

# Test auto-discovery
cd /opt/plug-monitor/03_auto_discovery
../venv/bin/python auto_discovery.py --once
```

### Access Dashboard
Open browser: `http://<rpi-ip>:8080`

Default credentials (change immediately):
- Username: `admin`
- Password: (set during installation)

### First Scan
1. Click **Start Scan**
2. Wait for completion
3. Check discovered hosts in Zabbix

## Troubleshooting

### Proxy Not Connecting
```bash
# Check config
grep ^Server /etc/zabbix/zabbix_proxy.conf

# Test connectivity
telnet <zabbix-server-ip> 10051

# Restart proxy
sudo systemctl restart zabbix-proxy
```

### Dashboard Not Accessible
```bash
# Check service
sudo systemctl status zabbix-dashboard

# Check logs
sudo journalctl -u zabbix-dashboard -n 50

# Check port
sudo netstat -tlnp | grep 8080
```

### Auto-Discovery Not Working
```bash
# Check service
sudo systemctl status zabbix-autodiscovery

# Check API connectivity
curl http://<zabbix-server>/api_jsonrpc.php

# Verify config
cat /opt/plug-monitor/config/config.yml
```

### Network Scan Fails
```bash
# Test nmap manually
sudo nmap -sn 192.168.1.0/24

# Check permissions
ls -la /opt/plug-monitor/data/scans
```

## Upgrading

### From v1.0 to v1.1
```bash
cd /opt/plug-monitor
git pull origin main
sudo ./update.sh
```

## Uninstallation
```bash
# Stop services
sudo systemctl stop zabbix-proxy zabbix-autodiscovery zabbix-dashboard
sudo systemctl disable zabbix-proxy zabbix-autodiscovery zabbix-dashboard

# Remove packages
sudo apt remove --purge zabbix-proxy-sqlite3

# Remove files
sudo rm -rf /opt/plug-monitor
sudo rm -rf /var/log/plug-monitor
sudo rm /etc/systemd/system/zabbix-autodiscovery.service
sudo rm /etc/systemd/system/zabbix-dashboard.service

sudo systemctl daemon-reload
```

## Support
- Documentation: https://docs.plug-monitor.com
- Issues: support@plug-monitor.com
- Forum: https://community.plug-monitor.com