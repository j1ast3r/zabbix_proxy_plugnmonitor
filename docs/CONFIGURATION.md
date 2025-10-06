# Configuration Guide - Plug & Monitor

## Configuration Files

```
/opt/plug-monitor/config/
├── config.yml              # Main configuration
├── discovery.yml           # Discovery rules
└── templates.yml           # Template mappings

/etc/zabbix/
└── zabbix_proxy.conf       # Zabbix Proxy config
```

## Main Configuration (config.yml)

### Zabbix Settings
```yaml
zabbix:
  server: 192.168.1.10           # Zabbix Server IP
  server_port: 10051
  api_url: http://192.168.1.10/api_jsonrpc.php
  api_user: Admin
  api_password: zabbix           # Change in production!
  proxy_name: PlugMonitor-Proxy-RPI001
```

**Security:** Store credentials securely, use environment variables in production.

### Network Scanning
```yaml
network:
  scan_range: 192.168.1.0/24     # CIDR notation
  scan_interval: 3600             # seconds
  nmap_options: "-sn -T4"
  exclude_ips:
    - 192.168.1.1                 # Gateway
    - 192.168.1.10                # Zabbix Server
```

**Multiple Networks:**
```yaml
scan_ranges:
  - 192.168.1.0/24
  - 192.168.2.0/24
  - 10.0.0.0/24
```

### Discovery Settings
```yaml
discovery:
  enabled: true
  auto_add_hosts: true
  auto_apply_templates: true
  check_interval: 60
  
  default_groups:
    - "Discovered hosts"
    - "PlugMonitor"
  
  template_mapping:
    windows:
      - "Windows by Zabbix agent active"
    linux:
      - "Linux by Zabbix agent active"
    network_device:
      - "Generic SNMP"
```

### Dashboard Settings
```yaml
dashboard:
  host: 0.0.0.0
  port: 8080
  admin_user: admin
  admin_password: changeme       # Change immediately!
  secret_key: <generate-random>
```

Generate secret key:
```bash
openssl rand -hex 32
```

## Zabbix Proxy Configuration

File: `/etc/zabbix/zabbix_proxy.conf`

### Basic Settings
```ini
Server=192.168.1.10
ServerPort=10051
Hostname=PlugMonitor-Proxy-RPI001
DBName=/var/lib/zabbix/zabbix_proxy.db
```

### Performance Tuning (RPi 4GB)
```ini
StartPollers=5
StartTrappers=5
StartPingers=1
CacheSize=32M
HistoryCacheSize=16M
```

### Performance Tuning (RPi 8GB)
```ini
StartPollers=8
StartTrappers=8
StartPingers=2
CacheSize=64M
HistoryCacheSize=32M
```

### PSK Encryption
```ini
TLSConnect=psk
TLSAccept=psk
TLSPSKIdentity=PSK-PlugMonitor-001
TLSPSKFile=/etc/zabbix/zabbix_proxy.psk
```

Generate PSK:
```bash
openssl rand -hex 32 | sudo tee /etc/zabbix/zabbix_proxy.psk
sudo chown zabbix:zabbix /etc/zabbix/zabbix_proxy.psk
sudo chmod 600 /etc/zabbix/zabbix_proxy.psk
```

## Advanced Configurations

### Template Mapping Rules

Create `templates.yml`:
```yaml
# Hostname pattern → Template
hostname_patterns:
  - pattern: "srv-*"
    templates:
      - "Linux by Zabbix agent active"
    groups:
      - "Servers"
  
  - pattern: "ws-*"
    templates:
      - "Windows by Zabbix agent active"
    groups:
      - "Workstations"

# Vendor → Template
vendor_mapping:
  cisco:
    template: "Cisco IOS SNMP"
    groups: ["Network devices", "Cisco"]
  
  hp:
    template: "HP printer SNMP"
    groups: ["Printers"]
```

### Active Directory Integration

File: `config.yml`
```yaml
active_directory:
  enabled: true
  server: dc.example.com
  port: 389
  use_ssl: false
  
  bind_dn: "CN=ZabbixService,OU=Service,DC=example,DC=com"
  bind_password: "password"
  
  base_dn: "OU=Computers,DC=example,DC=com"
  search_filter: "(objectClass=computer)"
  
  sync_interval: 3600
  auto_import: true
```

**LDAP Filters:**

Only enabled computers:
```
(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

Specific OU:
```
(&(objectClass=computer)(distinguishedName=*,OU=Workstations,*))
```

Windows servers only:
```
(&(objectClass=computer)(operatingSystem=*Server*))
```

### PSK Encryption for Agents

Enable in config.yml:
```yaml
psk:
  enabled: true
  auto_generate: true
  key_length: 256
  key_dir: /opt/plug-monitor/data/keys
```

Keys are auto-generated per host and stored in:
```
/opt/plug-monitor/data/keys/<hostname>.psk
```

### Custom User Parameters

Create `/etc/zabbix/zabbix_agent2.d/custom.conf` on agents:

```ini
# Monitor specific service
UserParameter=myapp.status,systemctl is-active myapp

# Custom script
UserParameter=custom.check,/usr/local/bin/check_script.sh

# With parameters
UserParameter=process.count[*],ps aux | grep -c "$1"
```

## Network Configuration

### Multiple Network Ranges

Edit `config.yml`:
```yaml
network:
  scan_configs:
    - name: "Office Network"
      range: 192.168.1.0/24
      interval: 3600
      
    - name: "Server Network"
      range: 10.0.0.0/24
      interval: 1800
      
    - name: "IoT Network"
      range: 192.168.100.0/24
      interval: 7200
```

### VLAN Scanning

For VLANs accessible from RPi:
```yaml
network:
  scan_range: 192.168.0.0/16  # Scan all VLANs 192.168.x.x
  exclude_ranges:
    - 192.168.255.0/24
```

### Custom nmap Options

Fast scan:
```yaml
nmap_options: "-sn -T5 --min-rate 1000"
```

Detailed scan:
```yaml
nmap_options: "-sn -PE -PP -PS22,80,443 -PA80,443"
```

OS detection:
```yaml
nmap_options: "-O -sV"
```

## Firewall Configuration

### UFW (Ubuntu/Debian)
```bash
# Essential ports
sudo ufw allow 22/tcp          # SSH
sudo ufw allow 8080/tcp        # Dashboard
sudo ufw allow 10050/tcp       # Agent → Proxy
sudo ufw allow 10051/tcp       # Proxy → Server

# SNMP (optional)
sudo ufw allow 161/udp

# Enable
sudo ufw enable
```

### Firewalld (CentOS/RHEL)
```bash
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=10050/tcp
sudo firewall-cmd --permanent --add-port=10051/tcp
sudo firewall-cmd --reload
```

## Performance Optimization

### For 10-50 Hosts
```yaml
# config.yml
discovery:
  check_interval: 60

# zabbix_proxy.conf
StartPollers=5
CacheSize=32M
```

### For 50-200 Hosts
```yaml
discovery:
  check_interval: 120

# Proxy config
StartPollers=8
CacheSize=64M
HistoryCacheSize=32M
```

### For 200+ Hosts
Use multiple proxies or upgrade hardware.

## Logging Configuration

```yaml
logging:
  level: INFO                    # DEBUG, INFO, WARNING, ERROR
  file: /var/log/plug-monitor/plug-monitor.log
  max_size: 10485760            # 10MB
  backup_count: 5
```

View logs:
```bash
# All logs
sudo tail -f /var/log/plug-monitor/plug-monitor.log

# Proxy logs
sudo tail -f /var/log/zabbix/zabbix_proxy.log

# Auto-discovery logs
sudo journalctl -u zabbix-autodiscovery -f

# Dashboard logs
sudo journalctl -u zabbix-dashboard -f
```

## Backup Configuration

Backup essential files:
```bash
#!/bin/bash
BACKUP_DIR="/backup/plug-monitor-$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Configs
cp -r /opt/plug-monitor/config $BACKUP_DIR/
cp /etc/zabbix/zabbix_proxy.conf $BACKUP_DIR/

# Data
cp -r /opt/plug-monitor/data $BACKUP_DIR/

# Database
cp /var/lib/zabbix/zabbix_proxy.db $BACKUP_DIR/

tar -czf plug-monitor-backup-$(date +%Y%m%d).tar.gz $BACKUP_DIR
```

Restore:
```bash
tar -xzf plug-monitor-backup-YYYYMMDD.tar.gz
sudo cp -r backup/config/* /opt/plug-monitor/config/
sudo systemctl restart zabbix-proxy zabbix-autodiscovery
```

## Testing Configuration

```bash
# Test proxy config
sudo zabbix_proxy -t /etc/zabbix/zabbix_proxy.conf

# Test scanner
cd /opt/plug-monitor/02_network_scanner
../venv/bin/python network_scanner.py --target 192.168.1.0/24

# Test auto-discovery
cd /opt/plug-monitor/03_auto_discovery
../venv/bin/python auto_discovery.py --once

# Test API connection
curl -X POST http://192.168.1.10/api_jsonrpc.php \
  -H "Content-Type: application/json-rpc" \
  -d '{"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1}'
```

## Reload Configuration

```bash
# Reload all
sudo systemctl restart zabbix-proxy
sudo systemctl restart zabbix-autodiscovery
sudo systemctl restart zabbix-dashboard

# Or reload config without restart
sudo systemctl reload zabbix-proxy
```