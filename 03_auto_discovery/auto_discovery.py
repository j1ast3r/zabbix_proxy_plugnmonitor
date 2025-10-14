#!/usr/bin/env python3
"""
Auto-Discovery Daemon for Plug & Monitor
Automatically adds discovered hosts to Zabbix Server via API
FINAL VERSION: Fixed proxy_id issue, correct template names, proper auth handling
"""

import json
import yaml
import time
import logging
import requests
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ZabbixAPI:
    """Zabbix API client with support for both authentication methods"""

    def __init__(self, url: str, user: str = None, password: str = None, api_token: str = None):
        self.url = url
        self.user = user
        self.password = password
        self.api_token = api_token
        self.auth_token = None
        self.headers = {'Content-Type': 'application/json-rpc'}

        # If API token provided, add to headers
        if self.api_token:
            self.headers['Authorization'] = f'Bearer {self.api_token}'

    def _call(self, method: str, params: Dict) -> Dict:
        """Make API call"""
        payload = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params,
            'id': 1
        }

        # Add auth token for username/password method (not needed for API token)
        if self.auth_token and method != 'user.login':
            payload['auth'] = self.auth_token

        try:
            response = requests.post(self.url, json=payload, headers=self.headers, timeout=10)
            response.raise_for_status()
            result = response.json()

            if 'error' in result:
                raise Exception(f"API error: {result['error']}")

            return result.get('result')

        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            raise

    def login(self) -> bool:
        """Authenticate with Zabbix"""
        try:
            # If using API token, authentication is in headers - just verify it works
            if self.api_token:
                logger.info("Using API token authentication")
                # Test the token by making a simple API call
                self._call('apiinfo.version', {})
                logger.info("Successfully authenticated with API token")
                return True

            # Otherwise use username/password authentication
            elif self.user and self.password:
                logger.info("Using username/password authentication")
                self.auth_token = self._call('user.login', {
                    'username': self.user,
                    'password': self.password
                })
                logger.info("Successfully authenticated with username/password")
                return True

            else:
                logger.error("No authentication credentials provided")
                return False

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False

    def get_proxy_id(self, proxy_name: str) -> Optional[str]:
        """Get proxy ID by name"""
        try:
            proxies = self._call('proxy.get', {
                'output': ['proxyid', 'name'],
                'filter': {'name': proxy_name}
            })

            if proxies:
                return proxies[0]['proxyid']

            logger.warning(f"Proxy not found: {proxy_name}")
            return None

        except Exception as e:
            logger.error(f"Error getting proxy: {e}")
            return None

    def get_host_groups(self, group_names: List[str]) -> List[str]:
        """Get or create host groups"""
        group_ids = []

        for group_name in group_names:
            try:
                # Try to find existing group
                groups = self._call('hostgroup.get', {
                    'output': ['groupid'],
                    'filter': {'name': group_name}
                })

                if groups:
                    group_ids.append({'groupid': groups[0]['groupid']})
                else:
                    # Create new group
                    result = self._call('hostgroup.create', {'name': group_name})
                    group_ids.append({'groupid': result['groupids'][0]})
                    logger.info(f"Created host group: {group_name}")

            except Exception as e:
                logger.error(f"Error with host group {group_name}: {e}")

        return group_ids

    def get_template_id(self, template_name: str) -> Optional[str]:
        """Get template ID by name"""
        try:
            templates = self._call('template.get', {
                'output': ['templateid'],
                'filter': {'host': template_name}
            })

            if templates:
                return templates[0]['templateid']

            logger.warning(f"Template not found: {template_name}")
            return None

        except Exception as e:
            logger.error(f"Error getting template: {e}")
            return None

    def host_exists(self, hostname: str, ip: str) -> bool:
        """Check if host already exists"""
        try:
            hosts = self._call('host.get', {
                'output': ['hostid'],
                'filter': {'host': hostname}
            })

            if hosts:
                return True

            # Also check by IP
            hosts = self._call('host.get', {
                'output': ['hostid'],
                'filter': {'ip': ip}
            })

            return len(hosts) > 0

        except Exception as e:
            logger.error(f"Error checking host existence: {e}")
            return False

    def create_host(self, host_data: Dict, proxy_id: Optional[str], group_ids: List[Dict],
                    template_ids: List[str]) -> Optional[str]:
        """Create host in Zabbix"""
        try:
            hostname = host_data['hostname']
            ip = host_data['ip']

            # Check if already exists
            if self.host_exists(hostname, ip):
                logger.info(f"Host already exists: {hostname} ({ip})")
                return None

            # Prepare host creation parameters
            params = {
                'host': hostname,
                'name': hostname,
                'groups': group_ids,
                'interfaces': [{
                    'type': 1,  # Agent
                    'main': 1,
                    'useip': 1,
                    'ip': ip,
                    'dns': '',
                    'port': '10050'
                }]
            }

            # FIXED: Only add proxy if it's valid (not None and not 0)
            # Otherwise hosts are monitored by server directly
            if proxy_id and proxy_id != '0':
                params['proxyid'] = proxy_id
            # If proxy_id is None or '0', don't add proxyid parameter at all

            # Add templates if specified
            if template_ids:
                params['templates'] = [{'templateid': tid} for tid in template_ids]

            # Add inventory
            params['inventory_mode'] = 0  # Manual
            params['inventory'] = {
                'type': host_data.get('device_type', 'unknown'),
                'os': host_data.get('os_guess', 'Unknown'),
                'vendor': host_data.get('vendor', ''),
                'macaddress_a': host_data.get('mac', '')
            }

            # Create host
            result = self._call('host.create', params)

            host_id = result['hostids'][0]
            logger.info(f"Created host: {hostname} ({ip}) - ID: {host_id}")

            return host_id

        except Exception as e:
            logger.error(f"Error creating host {host_data.get('hostname')}: {e}")
            return None


class AutoDiscovery:
    """Auto-discovery daemon"""

    def __init__(self, config_path: str = "/opt/plug-monitor/config/config.yml"):
        self.config = self._load_config(config_path)
        self.zapi = None
        self.proxy_id = None
        self.scan_data_dir = Path("/opt/plug-monitor/data/scans")
        self.processed_file = Path("/opt/plug-monitor/data/processed_hosts.json")
        self.processed_hosts = self._load_processed()

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            raise

    def _load_processed(self) -> set:
        """Load list of already processed hosts"""
        if self.processed_file.exists():
            try:
                with open(self.processed_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('hosts', []))
            except Exception as e:
                logger.error(f"Error loading processed hosts: {e}")

        return set()

    def _save_processed(self):
        """Save processed hosts list"""
        try:
            self.processed_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.processed_file, 'w') as f:
                json.dump({
                    'hosts': list(self.processed_hosts),
                    'updated': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving processed hosts: {e}")

    def connect_zabbix(self) -> bool:
        """Connect to Zabbix API"""
        try:
            zabbix_config = self.config['zabbix']

            # Get authentication credentials
            api_token = zabbix_config.get('api_token', '').strip()
            api_user = zabbix_config.get('api_user', '').strip()
            api_password = zabbix_config.get('api_password', '').strip()

            # CRITICAL FIX: Only use token if it's not empty
            use_token = bool(api_token)

            # Create API client with appropriate authentication
            self.zapi = ZabbixAPI(
                url=zabbix_config['api_url'],
                user=api_user if not use_token else None,
                password=api_password if not use_token else None,
                api_token=api_token if use_token else None
            )

            if not self.zapi.login():
                return False

            # Get proxy ID (optional - if proxy not found, hosts monitored by server)
            proxy_name = zabbix_config.get('proxy_name', '')
            if proxy_name:
                self.proxy_id = self.zapi.get_proxy_id(proxy_name)
                if not self.proxy_id:
                    logger.warning(f"Proxy '{proxy_name}' not found. Hosts will be monitored by server directly.")
                    self.proxy_id = None
            else:
                logger.info("No proxy configured. Hosts will be monitored by server directly.")
                self.proxy_id = None

            return True

        except Exception as e:
            logger.error(f"Error connecting to Zabbix: {e}")
            return False

    def get_template_for_host(self, host_data: Dict) -> List[str]:
        """Determine which templates to apply"""
        templates = []
        device_type = host_data.get('device_type', 'unknown')
        os_guess = host_data.get('os_guess', 'Unknown')

        # Get template mapping from config
        template_mapping = self.config.get('discovery', {}).get('template_mapping', {})

        # Template mapping logic
        if 'Linux' in os_guess:
            template_names = template_mapping.get('linux', ['Template OS Linux'])
            for template_name in template_names:
                template_id = self.zapi.get_template_id(template_name)
                if template_id:
                    templates.append(template_id)

        elif 'Windows' in os_guess:
            template_names = template_mapping.get('windows', ['Template OS Windows'])
            for template_name in template_names:
                template_id = self.zapi.get_template_id(template_name)
                if template_id:
                    templates.append(template_id)

        elif device_type == 'network_device':
            template_names = template_mapping.get('network_device', ['Template Net Network Generic Device SNMPv2'])
            for template_name in template_names:
                template_id = self.zapi.get_template_id(template_name)
                if template_id:
                    templates.append(template_id)

        elif device_type == 'printer':
            template_names = template_mapping.get('printer', ['Template Module Generic SNMPv2'])
            for template_name in template_names:
                template_id = self.zapi.get_template_id(template_name)
                if template_id:
                    templates.append(template_id)

        # Fallback to ICMP if no specific template
        if not templates:
            fallback_names = template_mapping.get('unknown', ['Template Module ICMP Ping'])
            for template_name in fallback_names:
                template_id = self.zapi.get_template_id(template_name)
                if template_id:
                    templates.append(template_id)

        return templates

    def process_scan_results(self):
        """Process latest scan results"""
        latest_scan = self.scan_data_dir / "latest.json"

        if not latest_scan.exists():
            logger.warning("No scan results found")
            return

        try:
            with open(latest_scan, 'r') as f:
                data = json.load(f)

            hosts = data.get('hosts', [])
            logger.info(f"Processing {len(hosts)} discovered hosts")

            # Get default host groups
            discovery_config = self.config.get('discovery', {})
            default_groups = discovery_config.get('default_groups', ['Discovered hosts'])
            group_ids = self.zapi.get_host_groups(default_groups)

            added_count = 0
            skipped_count = 0

            for host in hosts:
                host_key = f"{host['ip']}_{host['hostname']}"

                # Skip if already processed
                if host_key in self.processed_hosts:
                    skipped_count += 1
                    continue

                # Get templates
                template_ids = self.get_template_for_host(host)

                # Create host WITH PROXY (for remote monitoring)
                host_id = self.zapi.create_host(
                    host_data=host,
                    proxy_id=self.proxy_id,  # Use proxy for monitoring
                    group_ids=group_ids,
                    template_ids=template_ids
                )

                if host_id:
                    added_count += 1
                    self.processed_hosts.add(host_key)
                else:
                    skipped_count += 1

            logger.info(f"Added {added_count} new hosts, skipped {skipped_count}")

            # Save processed hosts
            self._save_processed()

        except Exception as e:
            logger.error(f"Error processing scan results: {e}")

    def run(self, interval: int = 60):
        """Run auto-discovery daemon"""
        logger.info("Starting Auto-Discovery daemon")

        if not self.connect_zabbix():
            logger.error("Failed to connect to Zabbix. Exiting.")
            return

        logger.info(f"Monitoring scan directory: {self.scan_data_dir}")
        logger.info(f"Check interval: {interval} seconds")

        while True:
            try:
                self.process_scan_results()
                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Shutting down...")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(interval)


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Zabbix Auto-Discovery Daemon')
    parser.add_argument('--config', '-c',
                        default='/opt/plug-monitor/config/config.yml',
                        help='Config file path')
    parser.add_argument('--interval', '-i', type=int, default=60,
                        help='Check interval in seconds')
    parser.add_argument('--once', action='store_true',
                        help='Run once and exit')

    args = parser.parse_args()

    discovery = AutoDiscovery(config_path=args.config)

    if args.once:
        # Run once
        if discovery.connect_zabbix():
            discovery.process_scan_results()
    else:
        # Run as daemon
        discovery.run(interval=args.interval)


if __name__ == '__main__':
    main()