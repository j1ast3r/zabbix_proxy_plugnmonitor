#!/usr/bin/env python3
"""
Auto-Discovery Daemon for Plug & Monitor
Automatically adds discovered hosts to Zabbix Server via API
+ Auto-creates dashboard with graphs for all monitored hosts
"""

import json
import yaml
import time
import logging
import requests
import re
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
        """Get proxy ID by name - REQUIRED for remote monitoring"""
        try:
            logger.info(f"Looking for REQUIRED proxy: {proxy_name}")

            proxies = self._call('proxy.get', {
                'output': ['proxyid', 'name'],
                'filter': {'name': proxy_name}
            })

            logger.info(f"Proxy API response: {proxies}")

            if proxies and len(proxies) > 0:
                proxy = proxies[0]
                proxy_id = proxy['proxyid']

                if proxy_id and proxy_id != '0' and proxy_id != 0:
                    logger.info(f"✅ Found proxy '{proxy_name}' with ID: {proxy_id}")
                    return str(proxy_id)
                else:
                    logger.error(f"❌ Proxy '{proxy_name}' has invalid ID: {proxy_id}")
                    return None
            else:
                logger.error(f"❌ CRITICAL: Proxy '{proxy_name}' not found in Zabbix Server!")
                logger.error(f"   Please create proxy in Zabbix Web:")
                logger.error(f"   Administration → Proxies → Create proxy")
                logger.error(f"   Proxy name: {proxy_name}")
                logger.error(f"   Proxy mode: Active")
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
                'output': ['templateid', 'host'],
                'filter': {'host': template_name}
            })

            if templates:
                logger.debug(f"Found template '{template_name}': {templates[0]['templateid']}")
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

    @staticmethod
    def sanitize_hostname(hostname: str) -> str:
        """
        Sanitize hostname to comply with Zabbix requirements
        Allowed: alphanumeric, '.', ' ', '_', '-'
        """
        # Replace invalid characters with underscore
        sanitized = re.sub(r'[^a-zA-Z0-9.\s_-]', '_', hostname)

        # Remove multiple consecutive underscores
        sanitized = re.sub(r'_+', '_', sanitized)

        # Trim underscores from start/end
        sanitized = sanitized.strip('_')

        if sanitized != hostname:
            logger.info(f"Sanitized hostname: '{hostname}' -> '{sanitized}'")

        return sanitized

    def create_host(self, host_data: Dict, proxy_id: str, group_ids: List[Dict],
                    template_ids: List[str], device_type: str) -> Optional[str]:
        """Create host in Zabbix - proxy_id is REQUIRED"""
        try:
            hostname = self.sanitize_hostname(host_data['hostname'])
            ip = host_data['ip']

            # Check if already exists
            if self.host_exists(hostname, ip):
                logger.info(f"Host already exists: {hostname} ({ip})")
                return None

            # CRITICAL: proxy_id is REQUIRED for remote monitoring
            if not proxy_id or str(proxy_id) == '0':
                logger.error(f"Cannot create host {hostname}: proxy_id is required but not available!")
                return None

            # Prepare host creation parameters
            params = {
                'host': hostname,
                'name': hostname,
                'groups': group_ids,
                'proxyid': str(proxy_id)  # ALWAYS use proxy for remote network
            }

            # CRITICAL FIX: Create appropriate interface based on device type
            if device_type in ['network_device', 'printer']:
                # SNMP interface for network devices and printers
                params['interfaces'] = [{
                    'type': 2,  # SNMP
                    'main': 1,
                    'useip': 1,
                    'ip': ip,
                    'dns': '',
                    'port': '161',
                    'details': {
                        'version': 2,  # SNMPv2
                        'community': '{$SNMP_COMMUNITY}'  # Will use macro
                    }
                }]
                logger.debug(f"Creating {device_type} with SNMP interface via proxy {proxy_id}")
            else:
                # Agent interface for all other devices
                params['interfaces'] = [{
                    'type': 1,  # Agent
                    'main': 1,
                    'useip': 1,
                    'ip': ip,
                    'dns': '',
                    'port': '10050'
                }]
                logger.debug(f"Creating {device_type} with Agent interface via proxy {proxy_id}")

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

            logger.debug(f"Creating host with params: {json.dumps(params, indent=2)}")

            # Create host
            result = self._call('host.create', params)

            host_id = result['hostids'][0]
            logger.info(f"✅ Created host: {hostname} ({ip}) via proxy {proxy_id} - ID: {host_id}")

            return host_id

        except Exception as e:
            logger.error(f"Error creating host {host_data.get('hostname')}: {e}")
            return None

    def get_hosts_by_proxy(self, proxy_id: str) -> List[Dict]:
        """Get all hosts monitored by specific proxy"""
        try:
            hosts = self._call('host.get', {
                'output': ['hostid', 'host', 'name'],
                'proxyids': [proxy_id],
                'sortfield': 'name'
            })

            logger.info(f"Found {len(hosts)} hosts monitored by proxy {proxy_id}")
            return hosts

        except Exception as e:
            logger.error(f"Error getting hosts by proxy: {e}")
            return []

    def get_host_graphs(self, hostid: str) -> List[Dict]:
        """Get graphs for specific host"""
        try:
            graphs = self._call('graph.get', {
                'output': ['graphid', 'name'],
                'hostids': [hostid],
                'sortfield': 'name',
                'limit': 10  # Top 10 graphs per host
            })

            return graphs

        except Exception as e:
            logger.error(f"Error getting graphs for host {hostid}: {e}")
            return []

    def get_dashboard_id(self, dashboard_name: str) -> Optional[str]:
        """Check if dashboard already exists"""
        try:
            dashboards = self._call('dashboard.get', {
                'output': ['dashboardid', 'name'],
                'filter': {'name': dashboard_name}
            })

            if dashboards:
                return dashboards[0]['dashboardid']

            return None

        except Exception as e:
            logger.error(f"Error checking dashboard existence: {e}")
            return None

    def create_dashboard(self, proxy_name: str, proxy_id: str) -> Optional[str]:
        """Create dashboard with graphs for all hosts monitored by proxy"""
        try:
            dashboard_name = f"Dashboard - {proxy_name}"

            # Check if already exists
            existing_id = self.get_dashboard_id(dashboard_name)
            if existing_id:
                logger.info(f"Dashboard '{dashboard_name}' already exists (ID: {existing_id}), will update it")
                return self.update_dashboard(existing_id, proxy_id, proxy_name)

            logger.info(f"Creating dashboard: {dashboard_name}")

            # Get all hosts for this proxy
            hosts = self.get_hosts_by_proxy(proxy_id)

            if not hosts:
                logger.warning(f"No hosts found for proxy {proxy_id}, skipping dashboard creation")
                return None

            # Build widgets
            widgets = []

            # 1. Summary widget - Problems by severity
            widgets.append({
                'type': 'problemsbysv',
                'name': f'{proxy_name} - Problems',
                'x': 0,
                'y': 0,
                'width': 12,
                'height': 5,
                'fields': [
                    {'type': 1, 'name': 'show_suppressed', 'value': 0}
                ]
            })

            # 2. Host availability widget
            widgets.append({
                'type': 'hostavail',
                'name': f'{proxy_name} - Host Availability',
                'x': 12,
                'y': 0,
                'width': 12,
                'height': 5,
                'fields': []
            })

            # 3. Add graph widgets for each host (2 per row)
            y_position = 5
            x_position = 0
            widget_width = 12
            widget_height = 5

            for idx, host in enumerate(hosts[:20]):  # Limit to 20 hosts to avoid huge dashboard
                hostid = host['hostid']
                hostname = host['name']

                # Get graphs for this host
                graphs = self.get_host_graphs(hostid)

                if not graphs:
                    # If no graphs, add CPU utilization widget
                    widgets.append({
                        'type': 'item',
                        'name': f'{hostname} - Status',
                        'x': x_position,
                        'y': y_position,
                        'width': widget_width,
                        'height': widget_height,
                        'fields': [
                            {'type': 0, 'name': 'itemid', 'value': ''},  # Will show host status
                            {'type': 0, 'name': 'description', 'value': hostname}
                        ]
                    })
                else:
                    # Add first graph for this host
                    graph = graphs[0]
                    widgets.append({
                        'type': 'graph',
                        'name': f'{hostname}',
                        'x': x_position,
                        'y': y_position,
                        'width': widget_width,
                        'height': widget_height,
                        'fields': [
                            {'type': 0, 'name': 'graphid', 'value': graph['graphid']}
                        ]
                    })

                # Position for next widget
                x_position += widget_width
                if x_position >= 24:  # Zabbix dashboard is 24 units wide
                    x_position = 0
                    y_position += widget_height

            # Create dashboard
            params = {
                'name': dashboard_name,
                'display_period': 30,
                'auto_start': 1,
                'pages': [{
                    'name': 'Overview',
                    'widgets': widgets
                }]
            }

            result = self._call('dashboard.create', params)
            dashboard_id = result['dashboardids'][0]

            logger.info(f"✅ Created dashboard '{dashboard_name}' with {len(widgets)} widgets - ID: {dashboard_id}")
            return dashboard_id

        except Exception as e:
            logger.error(f"Error creating dashboard: {e}")
            return None

    def update_dashboard(self, dashboard_id: str, proxy_id: str, proxy_name: str) -> Optional[str]:
        """Update existing dashboard with current hosts"""
        try:
            logger.info(f"Updating dashboard ID {dashboard_id} for proxy {proxy_name}")

            # Get current dashboard
            dashboards = self._call('dashboard.get', {
                'output': 'extend',
                'selectPages': 'extend',
                'dashboardids': [dashboard_id]
            })

            if not dashboards:
                logger.error(f"Dashboard {dashboard_id} not found")
                return None

            dashboard = dashboards[0]

            # Get all hosts for this proxy
            hosts = self.get_hosts_by_proxy(proxy_id)

            if not hosts:
                logger.warning(f"No hosts found for proxy {proxy_id}")
                return dashboard_id

            # Rebuild widgets
            widgets = []

            # 1. Summary widget
            widgets.append({
                'type': 'problemsbysv',
                'name': f'{proxy_name} - Problems',
                'x': 0,
                'y': 0,
                'width': 12,
                'height': 5,
                'fields': [
                    {'type': 1, 'name': 'show_suppressed', 'value': 0}
                ]
            })

            # 2. Host availability
            widgets.append({
                'type': 'hostavail',
                'name': f'{proxy_name} - Host Availability',
                'x': 12,
                'y': 0,
                'width': 12,
                'height': 5,
                'fields': []
            })

            # 3. Add graphs
            y_position = 5
            x_position = 0
            widget_width = 12
            widget_height = 5

            for host in hosts[:20]:
                hostid = host['hostid']
                hostname = host['name']

                graphs = self.get_host_graphs(hostid)

                if not graphs:
                    widgets.append({
                        'type': 'item',
                        'name': f'{hostname} - Status',
                        'x': x_position,
                        'y': y_position,
                        'width': widget_width,
                        'height': widget_height,
                        'fields': [
                            {'type': 0, 'name': 'description', 'value': hostname}
                        ]
                    })
                else:
                    graph = graphs[0]
                    widgets.append({
                        'type': 'graph',
                        'name': f'{hostname}',
                        'x': x_position,
                        'y': y_position,
                        'width': widget_width,
                        'height': widget_height,
                        'fields': [
                            {'type': 0, 'name': 'graphid', 'value': graph['graphid']}
                        ]
                    })

                x_position += widget_width
                if x_position >= 24:
                    x_position = 0
                    y_position += widget_height

            # Update dashboard
            params = {
                'dashboardid': dashboard_id,
                'pages': [{
                    'name': 'Overview',
                    'widgets': widgets
                }]
            }

            self._call('dashboard.update', params)

            logger.info(f"✅ Updated dashboard with {len(widgets)} widgets")
            return dashboard_id

        except Exception as e:
            logger.error(f"Error updating dashboard: {e}")
            return None


class AutoDiscovery:
    """Auto-discovery daemon"""

    def __init__(self, config_path: str = "/opt/plug-monitor/config/config.yml"):
        self.config = self._load_config(config_path)
        self.zapi = None
        self.proxy_id = None
        self.proxy_name = None
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

            # CRITICAL: Get proxy ID - REQUIRED for remote network monitoring
            self.proxy_name = zabbix_config.get('proxy_name', '')
            if not self.proxy_name:
                logger.error("❌ CRITICAL: proxy_name not configured in config.yml!")
                logger.error("   Remote network monitoring requires a proxy!")
                return False

            self.proxy_id = self.zapi.get_proxy_id(self.proxy_name)

            if not self.proxy_id:
                logger.error("❌ CRITICAL: Proxy not found! Cannot continue without proxy.")
                logger.error("   Please create proxy in Zabbix Server first:")
                logger.error("   1. Go to Administration → Proxies → Create proxy")
                logger.error(f"   2. Proxy name: {self.proxy_name}")
                logger.error("   3. Proxy mode: Active")
                logger.error("   4. Wait for proxy to connect (check proxy logs)")
                return False

            logger.info(f"✅ Using proxy: {self.proxy_name} (ID: {self.proxy_id})")
            logger.info(f"✅ All hosts will be monitored via this proxy")
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

        logger.debug(f"Getting templates for {host_data['hostname']}: type={device_type}, os={os_guess}")

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

        logger.debug(f"Selected templates for {host_data['hostname']}: {templates}")
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
                device_type = host.get('device_type', 'unknown')

                # Create host WITH proxy (REQUIRED for remote monitoring)
                host_id = self.zapi.create_host(
                    host_data=host,
                    proxy_id=self.proxy_id,  # REQUIRED
                    group_ids=group_ids,
                    template_ids=template_ids,
                    device_type=device_type
                )

                if host_id:
                    added_count += 1
                    self.processed_hosts.add(host_key)
                else:
                    skipped_count += 1

            logger.info(f"Added {added_count} new hosts, skipped {skipped_count}")

            # Save processed hosts
            self._save_processed()

            # Create or update dashboard if hosts were added
            if added_count > 0:
                logger.info("📊 Creating/updating dashboard with new hosts...")
                self.zapi.create_dashboard(self.proxy_name, self.proxy_id)

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
    parser.add_argument('--create-dashboard', action='store_true',
                        help='Force create/update dashboard')

    args = parser.parse_args()

    discovery = AutoDiscovery(config_path=args.config)

    if not discovery.connect_zabbix():
        logger.error("Failed to connect to Zabbix")
        return

    if args.create_dashboard:
        # Just create dashboard
        logger.info("Creating dashboard...")
        discovery.zapi.create_dashboard(discovery.proxy_name, discovery.proxy_id)
    elif args.once:
        # Run once
        discovery.process_scan_results()
    else:
        # Run as daemon
        discovery.run(interval=args.interval)


if __name__ == '__main__':
    main()