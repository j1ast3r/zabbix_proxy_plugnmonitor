#!/usr/bin/env python3
"""
Auto-Discovery Daemon for Plug & Monitor
Automatically adds discovered hosts to Zabbix Server via API
FIXED VERSION: Proper proxy assignment, better error handling, force re-add capability
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

        if self.auth_token and method != 'user.login':
            payload['auth'] = self.auth_token

        try:
            response = requests.post(self.url, json=payload, headers=self.headers, timeout=10)
            response.raise_for_status()
            result = response.json()

            if 'error' in result:
                error_msg = result['error'].get('data', result['error'].get('message', 'Unknown error'))
                raise Exception(f"API error: {error_msg}")

            return result.get('result')

        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            raise

    def login(self) -> bool:
        """Authenticate with Zabbix"""
        try:
            if self.api_token:
                logger.info("Using API token authentication")
                self._call('apiinfo.version', {})
                logger.info("Successfully authenticated with API token")
                return True
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
        """Get proxy ID by name

        Returns:
            Proxy ID as string (can be converted to int) or None if not found
        """
        try:
            proxies = self._call('proxy.get', {
                'output': ['proxyid', 'name'],
                'filter': {'name': proxy_name}
            })

            if proxies:
                proxy_id = str(proxies[0]['proxyid'])  # Ensure it's string
                logger.info(f"Found proxy '{proxy_name}' with ID: {proxy_id}")

                # Validate that it's a valid number
                try:
                    int(proxy_id)
                except ValueError:
                    logger.error(f"Proxy ID is not a valid number: {proxy_id}")
                    return None

                return proxy_id

            logger.warning(f"Proxy not found: {proxy_name}")
            return None

        except Exception as e:
            logger.error(f"Error getting proxy: {e}")
            return None

    def get_host_groups(self, group_names: List[str]) -> List[Dict]:
        """Get or create host groups"""
        group_ids = []

        for group_name in group_names:
            try:
                groups = self._call('hostgroup.get', {
                    'output': ['groupid', 'name'],
                    'filter': {'name': group_name}
                })

                if groups:
                    group_ids.append({'groupid': groups[0]['groupid']})
                    logger.debug(f"Found group: {group_name}")
                else:
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
                'output': ['templateid', 'host'],
                'filter': {'host': template_name}
            })

            if templates:
                template_id = templates[0]['templateid']
                logger.debug(f"Found template '{template_name}': {template_id}")
                return template_id

            logger.warning(f"Template not found: {template_name}")
            return None

        except Exception as e:
            logger.error(f"Error getting template: {e}")
            return None

    def host_exists(self, hostname: str) -> Optional[Dict]:
        """Check if host exists and return host info"""
        try:
            hosts = self._call('host.get', {
                'output': ['hostid', 'host', 'name', 'status'],
                'selectGroups': ['groupid', 'name'],
                'selectParentTemplates': ['templateid', 'host'],
                'filter': {'host': hostname}
            })

            if hosts:
                host = hosts[0]
                logger.debug(f"Host exists: {hostname} (ID: {host['hostid']})")
                return host

            return None

        except Exception as e:
            logger.error(f"Error checking host existence: {e}")
            return None

    def delete_host(self, host_id: str) -> bool:
        """Delete host from Zabbix"""
        try:
            self._call('host.delete', [host_id])
            logger.info(f"Deleted host ID: {host_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting host {host_id}: {e}")
            return False

    def create_host(self, host_data: Dict, proxy_id: Optional[str], group_ids: List[Dict],
                    template_ids: List[str], force: bool = False) -> Dict:
        """Create host in Zabbix

        Returns:
            Dict with 'success': bool, 'host_id': str (if success), 'error': str (if failure)
        """
        try:
            hostname = host_data['hostname']
            ip = host_data['ip']

            # Network scanner now queries agents directly for their hostname
            # So we can trust the hostname we receive!
            agent_detected = host_data.get('agent_detected', False)

            if agent_detected:
                logger.info(f"Host {hostname} has Zabbix agent - using agent's hostname")
            else:
                logger.info(f"Host {hostname} has no agent - using DNS name")

            # Check if already exists
            existing = self.host_exists(hostname)
            if existing:
                if force:
                    logger.info(f"Force mode: Deleting existing host {hostname}")
                    if not self.delete_host(existing['hostid']):
                        return {
                            'success': False,
                            'error': f'Failed to delete existing host {hostname}'
                        }
                    time.sleep(1)
                else:
                    logger.info(f"Host already exists: {hostname} ({ip})")
                    return {
                        'success': True,
                        'host_id': existing['hostid'],
                        'message': 'Host already exists'
                    }

            # Validate inputs
            if not group_ids:
                return {
                    'success': False,
                    'error': 'No host groups specified'
                }

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

            # Add proxy if specified
            # CRITICAL: Zabbix 7.0 requires proxyid as INTEGER, not string!
            if proxy_id and proxy_id != '0':
                try:
                    params['proxyid'] = int(proxy_id)
                    logger.info(f"Adding host {hostname} with proxy ID: {int(proxy_id)}")
                except (ValueError, TypeError) as e:
                    logger.error(f"Invalid proxy ID format: {proxy_id}, error: {e}")
                    return {
                        'success': False,
                        'error': f'Invalid proxy ID format: {proxy_id}. Must be a number.'
                    }
            else:
                logger.info(f"Adding host {hostname} without proxy (monitored by server)")

            # Add templates if specified
            if template_ids:
                params['templates'] = [{'templateid': tid} for tid in template_ids]
                logger.info(f"Applying templates: {template_ids}")
            else:
                logger.warning(f"No templates found for host {hostname}")

            # Add inventory
            params['inventory_mode'] = 0  # Manual
            params['inventory'] = {
                'type': host_data.get('device_type', 'unknown'),
                'os': host_data.get('os_guess', 'Unknown'),
                'vendor': host_data.get('vendor', ''),
                'macaddress_a': host_data.get('mac', ''),
                'notes': f"Agent detected: {agent_detected}"
            }

            # Create host
            logger.info(f"Creating host {hostname}...")
            logger.debug(f"Host creation params: {json.dumps(params, indent=2, default=str)}")

            result = self._call('host.create', params)
            host_id = result['hostids'][0]
            logger.info(f"✅ Created host: {hostname} ({ip}) - ID: {host_id}")

            return {
                'success': True,
                'host_id': host_id,
                'message': f'Host {hostname} created successfully'
            }

        except Exception as e:
            error_msg = str(e)
            logger.error(f"❌ Error creating host {host_data.get('hostname')}: {error_msg}")
            return {
                'success': False,
                'error': error_msg
            }

    def get_all_hosts(self) -> List[Dict]:
        """Get all hosts from Zabbix"""
        try:
            hosts = self._call('host.get', {
                'output': ['hostid', 'host', 'name', 'status'],
                'selectInterfaces': ['ip'],
                'selectGroups': ['name']
            })
            return hosts
        except Exception as e:
            logger.error(f"Error getting all hosts: {e}")
            return []


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

            api_token = zabbix_config.get('api_token', '').strip()
            api_user = zabbix_config.get('api_user', '').strip()
            api_password = zabbix_config.get('api_password', '').strip()

            use_token = bool(api_token)

            self.zapi = ZabbixAPI(
                url=zabbix_config['api_url'],
                user=api_user if not use_token else None,
                password=api_password if not use_token else None,
                api_token=api_token if use_token else None
            )

            if not self.zapi.login():
                return False

            # Get proxy ID
            proxy_name = zabbix_config.get('proxy_name', '')
            if proxy_name:
                self.proxy_id = self.zapi.get_proxy_id(proxy_name)
                if not self.proxy_id:
                    logger.warning(f"Proxy '{proxy_name}' not found. Hosts will be monitored by server directly.")
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

        template_mapping = self.config.get('discovery', {}).get('template_mapping', {})

        # Template mapping logic
        if 'Linux' in os_guess:
            template_names = template_mapping.get('linux', ['Linux by Zabbix agent active'])
        elif 'Windows' in os_guess:
            template_names = template_mapping.get('windows', ['Windows by Zabbix agent active'])
        elif device_type == 'network_device':
            template_names = template_mapping.get('network_device', ['Generic SNMP'])
        elif device_type == 'printer':
            template_names = template_mapping.get('printer', ['Generic SNMP'])
        else:
            template_names = template_mapping.get('unknown', ['ICMP Ping'])

        for template_name in template_names:
            template_id = self.zapi.get_template_id(template_name)
            if template_id:
                templates.append(template_id)
            else:
                logger.warning(f"Template not found: {template_name}")

        return templates

    def process_scan_results(self, force_add: bool = False):
        """Process latest scan results"""
        latest_scan = self.scan_data_dir / "latest.json"

        if not latest_scan.exists():
            logger.warning("No scan results found")
            return

        try:
            with open(latest_scan, 'r') as f:
                data = json.load(f)

            hosts = data.get('hosts', [])
            logger.info(f"Processing {len(hosts)} discovered hosts (force_add={force_add})")

            discovery_config = self.config.get('discovery', {})
            default_groups = discovery_config.get('default_groups', ['Discovered hosts'])
            group_ids = self.zapi.get_host_groups(default_groups)

            added_count = 0
            skipped_count = 0
            error_count = 0

            for host in hosts:
                host_key = f"{host['ip']}_{host['hostname']}"

                # Skip if already processed (unless force_add)
                if not force_add and host_key in self.processed_hosts:
                    skipped_count += 1
                    continue

                # Get templates
                template_ids = self.get_template_for_host(host)

                # Create host
                result = self.zapi.create_host(
                    host_data=host,
                    proxy_id=self.proxy_id,
                    group_ids=group_ids,
                    template_ids=template_ids,
                    force=force_add
                )

                if result['success']:
                    added_count += 1
                    self.processed_hosts.add(host_key)
                    logger.info(f"✅ {host['hostname']}: {result.get('message', 'Added')}")
                else:
                    error_count += 1
                    logger.error(f"❌ {host['hostname']}: {result.get('error', 'Unknown error')}")

            logger.info(f"✅ Added: {added_count}, ⏭️  Skipped: {skipped_count}, ❌ Errors: {error_count}")

            # Save processed hosts
            self._save_processed()

        except Exception as e:
            logger.error(f"Error processing scan results: {e}")

    def add_single_host(self, host_data: Dict, force: bool = False) -> Dict:
        """Add a single host to Zabbix

        Returns:
            Dict with 'success': bool, 'message': str, 'error': str (if failed)
        """
        try:
            discovery_config = self.config.get('discovery', {})
            default_groups = discovery_config.get('default_groups', ['Discovered hosts'])
            group_ids = self.zapi.get_host_groups(default_groups)

            if not group_ids:
                return {
                    'success': False,
                    'error': 'Failed to get/create host groups'
                }

            template_ids = self.get_template_for_host(host_data)

            result = self.zapi.create_host(
                host_data=host_data,
                proxy_id=self.proxy_id,
                group_ids=group_ids,
                template_ids=template_ids,
                force=force
            )

            if result['success']:
                host_key = f"{host_data['ip']}_{host_data['hostname']}"
                self.processed_hosts.add(host_key)
                self._save_processed()
                return result
            else:
                return result

        except Exception as e:
            error_msg = f"Exception in add_single_host: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }

    def clear_processed_hosts(self):
        """Clear processed hosts list (for re-adding hosts)"""
        self.processed_hosts = set()
        self._save_processed()
        logger.info("Cleared processed hosts list")

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
    parser.add_argument('--force', action='store_true',
                        help='Force re-add all hosts (delete and recreate)')

    args = parser.parse_args()

    discovery = AutoDiscovery(config_path=args.config)

    if args.once:
        if discovery.connect_zabbix():
            discovery.process_scan_results(force_add=args.force)
    else:
        discovery.run(interval=args.interval)


if __name__ == '__main__':
    main()