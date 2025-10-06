#!/usr/bin/env python3
"""
Active Directory Synchronization for Plug & Monitor
Imports computer objects from AD and creates hosts in Zabbix
"""

import yaml
import logging
import time
import schedule
from datetime import datetime
from typing import List, Dict, Optional
from ldap3 import Server, Connection, ALL, SUBTREE

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ADSync:
    """Active Directory synchronization"""

    def __init__(self, config_path: str = "/opt/plug-monitor/config/config.yml"):
        self.config = self._load_config(config_path)
        self.ad_config = self.config.get('active_directory', {})
        self.server = None
        self.conn = None

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            raise

    def connect(self) -> bool:
        """Connect to Active Directory"""
        try:
            server_url = self.ad_config['server']
            port = self.ad_config.get('port', 389)
            use_ssl = self.ad_config.get('use_ssl', False)

            self.server = Server(
                server_url,
                port=port,
                use_ssl=use_ssl,
                get_info=ALL
            )

            bind_dn = self.ad_config['bind_dn']
            bind_password = self.ad_config['bind_password']

            self.conn = Connection(
                self.server,
                user=bind_dn,
                password=bind_password,
                auto_bind=True
            )

            logger.info(f"Connected to AD: {server_url}")
            return True

        except Exception as e:
            logger.error(f"AD connection failed: {e}")
            return False

    def get_computers(self) -> List[Dict]:
        """Get computer objects from AD"""
        if not self.conn:
            logger.error("Not connected to AD")
            return []

        try:
            base_dn = self.ad_config['base_dn']
            search_filter = self.ad_config.get('search_filter', '(objectClass=computer)')

            attributes = [
                'cn',
                'dNSHostName',
                'operatingSystem',
                'operatingSystemVersion',
                'description',
                'whenCreated',
                'lastLogon',
                'distinguishedName'
            ]

            self.conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes
            )

            computers = []
            for entry in self.conn.entries:
                computer = {
                    'name': str(entry.cn),
                    'fqdn': str(entry.dNSHostName) if entry.dNSHostName else None,
                    'os': str(entry.operatingSystem) if entry.operatingSystem else 'Unknown',
                    'os_version': str(entry.operatingSystemVersion) if entry.operatingSystemVersion else '',
                    'description': str(entry.description) if entry.description else '',
                    'created': str(entry.whenCreated) if entry.whenCreated else None,
                    'dn': str(entry.distinguishedName)
                }

                # Determine OS type
                os_lower = computer['os'].lower()
                if 'windows' in os_lower:
                    if 'server' in os_lower:
                        computer['device_type'] = 'server'
                        computer['template'] = 'Windows by Zabbix agent active'
                    else:
                        computer['device_type'] = 'workstation'
                        computer['template'] = 'Windows by Zabbix agent active'
                elif 'linux' in os_lower:
                    computer['device_type'] = 'server'
                    computer['template'] = 'Linux by Zabbix agent active'
                else:
                    computer['device_type'] = 'workstation'
                    computer['template'] = 'ICMP Ping'

                computers.append(computer)

            logger.info(f"Found {len(computers)} computers in AD")
            return computers

        except Exception as e:
            logger.error(f"Error querying AD: {e}")
            return []

    def sync_to_zabbix(self, computers: List[Dict]):
        """Synchronize computers to Zabbix"""
        # Import Zabbix API from auto_discovery module
        import sys
        sys.path.append('/opt/plug-monitor/03_auto_discovery')
        from auto_discovery import ZabbixAPI

        try:
            zabbix_config = self.config['zabbix']
            zapi = ZabbixAPI(
                url=zabbix_config['api_url'],
                user=zabbix_config['api_user'],
                password=zabbix_config['api_password']
            )

            if not zapi.login():
                logger.error("Failed to login to Zabbix")
                return

            # Get proxy ID
            proxy_id = zapi.get_proxy_id(zabbix_config['proxy_name'])

            # Get host groups
            group_ids = zapi.get_host_groups(['Active Directory', 'Windows computers'])

            added_count = 0
            skipped_count = 0

            for computer in computers:
                hostname = computer['fqdn'] if computer['fqdn'] else computer['name']

                # Check if host exists
                if zapi.host_exists(hostname, ''):
                    logger.debug(f"Host already exists: {hostname}")
                    skipped_count += 1
                    continue

                # Get template ID
                template_id = zapi.get_template_id(computer['template'])
                template_ids = [template_id] if template_id else []

                # Prepare host data
                host_data = {
                    'hostname': hostname,
                    'ip': '',  # Will be resolved by DNS
                    'device_type': computer['device_type'],
                    'os_guess': computer['os'],
                    'vendor': 'Microsoft' if 'windows' in computer['os'].lower() else '',
                    'mac': ''
                }

                # Create host
                host_id = zapi.create_host(
                    host_data=host_data,
                    proxy_id=proxy_id,
                    group_ids=group_ids,
                    template_ids=template_ids
                )

                if host_id:
                    logger.info(f"Added host: {hostname}")
                    added_count += 1
                else:
                    skipped_count += 1

            logger.info(f"Sync complete: Added {added_count}, Skipped {skipped_count}")

        except Exception as e:
            logger.error(f"Error syncing to Zabbix: {e}")

    def run_sync(self):
        """Run synchronization"""
        logger.info("Starting AD sync...")

        if not self.connect():
            logger.error("Cannot connect to AD")
            return

        computers = self.get_computers()

        if computers:
            self.sync_to_zabbix(computers)

        if self.conn:
            self.conn.unbind()

        logger.info("AD sync completed")

    def run_scheduled(self):
        """Run sync on schedule"""
        interval = self.ad_config.get('sync_interval', 3600)
        logger.info(f"Scheduling AD sync every {interval} seconds")

        # Run immediately
        self.run_sync()

        # Schedule periodic runs
        schedule.every(interval).seconds.do(self.run_sync)

        while True:
            try:
                schedule.run_pending()
                time.sleep(60)
            except KeyboardInterrupt:
                logger.info("Shutting down...")
                break
            except Exception as e:
                logger.error(f"Error in scheduler: {e}")
                time.sleep(60)


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Active Directory Sync')
    parser.add_argument('--config', '-c',
                        default='/opt/plug-monitor/config/config.yml',
                        help='Config file path')
    parser.add_argument('--once', action='store_true',
                        help='Run once and exit')

    args = parser.parse_args()

    ad_sync = ADSync(config_path=args.config)

    if args.once:
        ad_sync.run_sync()
    else:
        ad_sync.run_scheduled()


if __name__ == '__main__':
    main()