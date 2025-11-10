#!/usr/bin/env python3
"""
Diagnostic script for Plug & Monitor
Tests Zabbix connection and host creation
"""

import sys
import yaml
import json

sys.path.insert(0, '/opt/plug-monitor/03_auto_discovery')

from auto_discovery import AutoDiscovery


def main():
    print("=" * 60)
    print("Plug & Monitor - Diagnostic Tool")
    print("=" * 60)
    print()

    # Load config
    print("1. Loading configuration...")
    try:
        with open('/opt/plug-monitor/config/config.yml', 'r') as f:
            config = yaml.safe_load(f)
        print("   ✓ Configuration loaded")

        # Show auth method
        if config['zabbix'].get('api_token'):
            print("   ℹ Using API Token authentication")
        else:
            print("   ℹ Using Username/Password authentication")
            print(f"   ℹ Username: {config['zabbix'].get('api_user')}")

        print(f"   ℹ Zabbix Server: {config['zabbix']['server']}")
        print(f"   ℹ API URL: {config['zabbix']['api_url']}")
        print(f"   ℹ Proxy Name: {config['zabbix'].get('proxy_name')}")
    except Exception as e:
        print(f"   ✗ Failed to load config: {e}")
        return False
    print()

    # Initialize auto-discovery
    print("2. Initializing auto-discovery...")
    try:
        ad = AutoDiscovery('/opt/plug-monitor/config/config.yml')
        print("   ✓ Auto-discovery initialized")
    except Exception as e:
        print(f"   ✗ Failed to initialize: {e}")
        return False
    print()

    # Connect to Zabbix
    print("3. Connecting to Zabbix...")
    try:
        if ad.connect_zabbix():
            print("   ✓ Connected to Zabbix successfully")
            print(f"   ℹ Proxy ID: {ad.proxy_id}")
            print(f"   ℹ Proxy ID type: {type(ad.proxy_id)}")

            if ad.proxy_id:
                try:
                    proxy_int = int(ad.proxy_id)
                    print(f"   ✓ Proxy ID can be converted to int: {proxy_int}")
                    print("   ✓ Proxy found and will be used")
                except (ValueError, TypeError) as e:
                    print(f"   ✗ WARNING: Proxy ID cannot be converted to integer!")
                    print(f"   ℹ Error: {e}")
                    print("   ℹ This will cause 'Invalid parameter proxyid' error!")
            else:
                print("   ⚠ Proxy not found - hosts will be monitored by server directly")
        else:
            print("   ✗ Failed to connect to Zabbix")
            print("   ℹ Check:")
            print("      - Zabbix Server is accessible")
            print("      - API credentials are correct")
            print("      - API URL is correct")
            return False
    except Exception as e:
        print(f"   ✗ Connection error: {e}")
        return False
    print()

    # Get host groups
    print("4. Checking host groups...")
    try:
        groups = ad.zapi.get_host_groups(['Discovered hosts', 'PlugMonitor'])
        print(f"   ✓ Found/created {len(groups)} host groups")
        for group in groups:
            print(f"     - Group ID: {group['groupid']}")
    except Exception as e:
        print(f"   ✗ Error getting groups: {e}")
        return False
    print()

    # Check templates
    print("5. Checking templates...")
    template_names = [
        'Windows by Zabbix agent active',
        'Linux by Zabbix agent active',
        'Generic SNMP',
        'ICMP Ping'
    ]

    found_templates = []
    missing_templates = []

    for template_name in template_names:
        template_id = ad.zapi.get_template_id(template_name)
        if template_id:
            found_templates.append(template_name)
            print(f"   ✓ Found: {template_name}")
        else:
            missing_templates.append(template_name)
            print(f"   ✗ Missing: {template_name}")

    if missing_templates:
        print()
        print("   ⚠ Some templates are missing!")
        print("   ℹ Solutions:")
        print("      1. Import missing templates to Zabbix")
        print("      2. Update config.yml with correct template names")
        print("      3. Check: Data collection → Templates in Zabbix")
    print()

    # Check scan results
    print("6. Checking scan results...")
    try:
        scan_file = '/opt/plug-monitor/data/scans/latest.json'
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)

        hosts = scan_data.get('hosts', [])
        print(f"   ✓ Found scan results: {len(hosts)} hosts")

        if hosts:
            print()
            print("   Sample host from scan:")
            sample = hosts[0]
            print(f"     IP: {sample.get('ip')}")
            print(f"     Hostname: {sample.get('hostname')}")
            print(f"     Type: {sample.get('device_type')}")
            print(f"     OS: {sample.get('os_guess')}")
    except FileNotFoundError:
        print("   ⚠ No scan results found")
        print("   ℹ Run a network scan first")
    except Exception as e:
        print(f"   ✗ Error reading scan results: {e}")
    print()

    # Test host creation
    print("7. Testing host creation...")
    print("   Creating test host: test-diagnostic-host")

    test_host = {
        'ip': '192.168.1.254',
        'hostname': 'test-diagnostic-host',
        'device_type': 'workstation',
        'os_guess': 'Unknown',
        'mac': '00:00:00:00:00:00',
        'vendor': 'Test'
    }

    try:
        # Get templates
        template_ids = ad.get_template_for_host(test_host)
        if not template_ids:
            print("   ⚠ No templates found for this host type")
            print("   ℹ Will use ICMP Ping only")

        # Try to create host
        result = ad.zapi.create_host(
            host_data=test_host,
            proxy_id=ad.proxy_id,
            group_ids=groups,
            template_ids=template_ids,
            force=False
        )

        if result['success']:
            print(f"   ✓ Test host created successfully!")
            print(f"   ℹ Host ID: {result.get('host_id')}")
            print()
            print("   ⚠ CLEANUP: Delete test host from Zabbix manually:")
            print("      Configuration → Hosts → test-diagnostic-host → Delete")
        else:
            print(f"   ✗ Failed to create test host")
            print(f"   ℹ Error: {result.get('error')}")
            print()
            print("   Common issues:")
            print("      1. Template not found - check template names in config.yml")
            print("      2. Proxy not found - add proxy in Zabbix: Administration → Proxies")
            print("      3. Permission denied - check API user permissions")
            print("      4. Host already exists - delete it first")

    except Exception as e:
        print(f"   ✗ Exception during test: {e}")
        import traceback
        traceback.print_exc()

    print()
    print("=" * 60)
    print("Diagnostic complete")
    print("=" * 60)
    print()

    if missing_templates:
        print("⚠ ACTION REQUIRED: Import missing templates to Zabbix")

    if not ad.proxy_id:
        print("⚠ WARNING: Proxy not found - check proxy configuration")

    print()
    print("For detailed logs, check:")
    print("  sudo journalctl -u zabbix-autodiscovery -n 100")
    print()


if __name__ == '__main__':
    main()