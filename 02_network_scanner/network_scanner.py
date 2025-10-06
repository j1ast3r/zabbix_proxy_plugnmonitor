#!/usr/bin/env python3
"""
Network Scanner for Plug & Monitor
Discovers devices on network using nmap
"""

import nmap
import json
import yaml
import logging
import socket
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkScanner:
    """Network scanner using nmap"""

    def __init__(self, config_path: str = "/opt/plug-monitor/config/config.yml"):
        """Initialize scanner with configuration"""
        self.config = self._load_config(config_path)
        self.nm = nmap.PortScanner()
        self.data_dir = Path("/opt/plug-monitor/data/scans")
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config not found: {config_path}, using defaults")
            return {
                'network': {
                    'scan_range': '192.168.1.0/24',
                    'nmap_options': '-sn -T4',
                    'exclude_ips': []
                }
            }

    def scan_network(self, target: Optional[str] = None) -> List[Dict]:
        """
        Scan network for active hosts

        Args:
            target: Network range to scan (e.g., '192.168.1.0/24')
                   If None, uses config

        Returns:
            List of discovered hosts with details
        """
        if target is None:
            target = self.config['network']['scan_range']

        nmap_args = self.config['network'].get('nmap_options', '-sn -T4')
        exclude_ips = self.config['network'].get('exclude_ips', [])

        logger.info(f"Starting network scan: {target}")
        logger.info(f"Nmap arguments: {nmap_args}")

        try:
            # Perform scan
            self.nm.scan(hosts=target, arguments=nmap_args)

            hosts = []
            for host in self.nm.all_hosts():
                # Skip excluded IPs
                if host in exclude_ips:
                    logger.debug(f"Skipping excluded IP: {host}")
                    continue

                host_info = self._get_host_info(host)
                if host_info:
                    hosts.append(host_info)
                    logger.info(f"Found host: {host} - {host_info.get('hostname', 'unknown')}")

            logger.info(f"Scan complete. Found {len(hosts)} hosts")

            # Save results
            self._save_results(hosts)

            return hosts

        except Exception as e:
            logger.error(f"Scan error: {e}", exc_info=True)
            return []

    def _get_host_info(self, host: str) -> Optional[Dict]:
        """Extract detailed information about a host"""
        try:
            host_data = self.nm[host]

            # Get hostname
            hostname = host_data.hostname() if host_data.hostname() else self._resolve_hostname(host)

            # Get state
            state = host_data.state()

            if state != 'up':
                return None

            # Get MAC address and vendor
            mac = None
            vendor = None
            if 'mac' in host_data['addresses']:
                mac = host_data['addresses']['mac']
                if 'vendor' in host_data and mac in host_data['vendor']:
                    vendor = host_data['vendor'][mac]

            # Try to determine device type
            device_type = self._guess_device_type(hostname, vendor, host)

            # Try to determine OS
            os_guess = self._guess_os(hostname, vendor, device_type)

            # Get all addresses
            addresses = host_data.get('addresses', {})

            info = {
                'ip': host,
                'hostname': hostname,
                'mac': mac,
                'vendor': vendor,
                'state': state,
                'device_type': device_type,
                'os_guess': os_guess,
                'addresses': addresses,
                'discovered_at': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat()
            }

            return info

        except Exception as e:
            logger.error(f"Error getting info for {host}: {e}")
            return None

    def _resolve_hostname(self, ip: str) -> str:
        """Resolve IP to hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return ip

    def _guess_device_type(self, hostname: str, vendor: str, ip: str) -> str:
        """Guess device type based on hostname, vendor, and other clues"""
        hostname_lower = hostname.lower() if hostname else ""
        vendor_lower = vendor.lower() if vendor else ""

        # Network devices
        if any(x in hostname_lower for x in ['router', 'gateway', 'gw', 'switch', 'sw']):
            return 'network_device'
        if any(x in vendor_lower for x in ['cisco', 'juniper', 'mikrotik', 'ubiquiti', 'netgear', 'tp-link', 'd-link']):
            return 'network_device'

        # Servers
        if any(x in hostname_lower for x in ['server', 'srv', 'host', 'node', 'vm']):
            return 'server'

        # Workstations
        if any(x in hostname_lower for x in ['pc', 'desktop', 'workstation', 'ws', 'laptop', 'notebook']):
            return 'workstation'

        # Printers
        if any(x in hostname_lower for x in ['printer', 'print', 'mfp', 'hp', 'canon', 'epson']):
            return 'printer'
        if any(x in vendor_lower for x in ['hewlett', 'canon', 'epson', 'brother', 'xerox']):
            return 'printer'

        # IoT/Embedded
        if any(x in hostname_lower for x in ['iot', 'sensor', 'camera', 'cam', 'nvr', 'dvr']):
            return 'iot'
        if any(x in vendor_lower for x in ['raspberry', 'arduino', 'esp']):
            return 'iot'

        # Mobile devices
        if any(x in vendor_lower for x in ['apple', 'samsung', 'xiaomi', 'huawei']):
            if any(x in hostname_lower for x in ['iphone', 'ipad', 'android', 'mobile']):
                return 'mobile'

        # Default
        return 'unknown'

    def _guess_os(self, hostname: str, vendor: str, device_type: str) -> str:
        """Guess operating system"""
        hostname_lower = hostname.lower() if hostname else ""
        vendor_lower = vendor.lower() if vendor else ""

        # Windows
        if any(x in hostname_lower for x in ['win', 'windows', 'desktop', 'pc']):
            return 'Windows'
        if vendor_lower and 'microsoft' in vendor_lower:
            return 'Windows'

        # Linux
        if any(x in hostname_lower for x in ['linux', 'ubuntu', 'debian', 'centos', 'rhel']):
            return 'Linux'

        # macOS
        if any(x in hostname_lower for x in ['mac', 'imac', 'macbook']):
            return 'macOS'
        if vendor_lower and 'apple' in vendor_lower:
            if device_type == 'workstation':
                return 'macOS'

        # Network OS
        if device_type == 'network_device':
            if 'cisco' in vendor_lower:
                return 'Cisco IOS'
            elif 'mikrotik' in vendor_lower:
                return 'RouterOS'
            elif 'ubiquiti' in vendor_lower:
                return 'EdgeOS'
            return 'Network OS'

        # Printer OS
        if device_type == 'printer':
            return 'Printer Firmware'

        # IoT
        if device_type == 'iot':
            if 'raspberry' in vendor_lower:
                return 'Linux (Raspberry Pi)'
            return 'Embedded Linux'

        return 'Unknown'

    def deep_scan(self, host: str) -> Dict:
        """
        Perform detailed scan on specific host
        Includes OS detection and service discovery
        """
        logger.info(f"Deep scanning: {host}")

        try:
            # Scan with OS detection and version detection
            # -O: OS detection, -sV: version detection, -A: aggressive
            self.nm.scan(host, arguments='-O -sV -T4')

            host_info = self._get_host_info(host)

            if host in self.nm.all_hosts():
                host_data = self.nm[host]

                # OS detection results
                if 'osmatch' in host_data:
                    os_matches = []
                    for osmatch in host_data['osmatch']:
                        os_matches.append({
                            'name': osmatch['name'],
                            'accuracy': osmatch['accuracy']
                        })
                    host_info['os_matches'] = os_matches

                # Port scan results
                if 'tcp' in host_data:
                    services = []
                    for port in host_data['tcp'].keys():
                        port_info = host_data['tcp'][port]
                        services.append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info.get('name', ''),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', '')
                        })
                    host_info['services'] = services

            return host_info

        except Exception as e:
            logger.error(f"Deep scan error for {host}: {e}")
            return {}

    def _save_results(self, hosts: List[Dict]) -> None:
        """Save scan results to JSON file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = self.data_dir / f"scan_{timestamp}.json"

        # Also save as latest.json for easy access
        latest_file = self.data_dir / "latest.json"

        data = {
            'scan_time': datetime.now().isoformat(),
            'total_hosts': len(hosts),
            'hosts': hosts
        }

        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)

            with open(latest_file, 'w') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Results saved to {filename}")

        except Exception as e:
            logger.error(f"Error saving results: {e}")

    def load_latest_scan(self) -> Optional[Dict]:
        """Load most recent scan results"""
        latest_file = self.data_dir / "latest.json"

        try:
            with open(latest_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("No previous scan results found")
            return None
        except Exception as e:
            logger.error(f"Error loading scan results: {e}")
            return None


def main():
    """CLI interface for testing"""
    import argparse

    parser = argparse.ArgumentParser(description='Network Scanner')
    parser.add_argument('--target', '-t', help='Network to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--deep', '-d', help='Perform deep scan on specific host')
    parser.add_argument('--config', '-c', default='/opt/plug-monitor/config/config.yml',
                        help='Config file path')

    args = parser.parse_args()

    scanner = NetworkScanner(config_path=args.config)

    if args.deep:
        # Deep scan single host
        result = scanner.deep_scan(args.deep)
        print(json.dumps(result, indent=2))
    else:
        # Network scan
        results = scanner.scan_network(target=args.target)
        print(f"\nFound {len(results)} hosts:")
        for host in results:
            print(f"  {host['ip']:15} - {host['hostname']:30} - {host['device_type']}")


if __name__ == '__main__':
    main()