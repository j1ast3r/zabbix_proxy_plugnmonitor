#!/usr/bin/env python3
"""
Web Dashboard for Plug & Monitor
Flask-based web interface for network scanning and monitoring
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_cors import CORS
import yaml
import json
import logging
import threading
import time
from pathlib import Path
from datetime import datetime
from network_scanner import NetworkScanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-in-production'
CORS(app)

# Global variables
scanner = None
scan_in_progress = False
scan_results = []
config = {}

# Paths
CONFIG_PATH = "/opt/plug-monitor/config/config.yml"
DATA_DIR = Path("/opt/plug-monitor/data/scans")


def load_config():
    """Load configuration"""
    global config
    try:
        with open(CONFIG_PATH, 'r') as f:
            config = yaml.safe_load(f)
        app.config['SECRET_KEY'] = config['dashboard'].get('secret_key', 'change-me')
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        config = {
            'dashboard': {'port': 8080, 'host': '0.0.0.0'},
            'network': {'scan_range': '192.168.1.0/24'}
        }


def init_scanner():
    """Initialize network scanner"""
    global scanner
    try:
        scanner = NetworkScanner(CONFIG_PATH)
        logger.info("Network scanner initialized")
    except Exception as e:
        logger.error(f"Error initializing scanner: {e}")


def scan_background(target=None):
    """Run scan in background thread"""
    global scan_in_progress, scan_results

    try:
        scan_in_progress = True
        logger.info(f"Starting background scan: {target}")

        results = scanner.scan_network(target=target)
        scan_results = results

        logger.info(f"Background scan complete: {len(results)} hosts found")

    except Exception as e:
        logger.error(f"Background scan error: {e}")
    finally:
        scan_in_progress = False


# Routes

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start network scan"""
    global scan_in_progress

    if scan_in_progress:
        return jsonify({'status': 'error', 'message': 'Scan already in progress'}), 400

    try:
        data = request.get_json() or {}
        target = data.get('target', None)

        # Start scan in background thread
        thread = threading.Thread(target=scan_background, args=(target,))
        thread.daemon = True
        thread.start()

        return jsonify({
            'status': 'success',
            'message': 'Scan started',
            'target': target or config['network']['scan_range']
        })

    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/scan/status')
def scan_status():
    """Get current scan status"""
    return jsonify({
        'in_progress': scan_in_progress,
        'results_count': len(scan_results)
    })


@app.route('/api/scan/results')
def get_results():
    """Get latest scan results"""
    global scan_results

    # If no results in memory, load from file
    if not scan_results:
        latest = scanner.load_latest_scan()
        if latest:
            scan_results = latest.get('hosts', [])

    return jsonify({
        'hosts': scan_results,
        'total': len(scan_results),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/host/<ip>/deep-scan', methods=['POST'])
def deep_scan_host(ip):
    """Perform deep scan on specific host"""
    try:
        result = scanner.deep_scan(ip)
        return jsonify({
            'status': 'success',
            'host': result
        })
    except Exception as e:
        logger.error(f"Deep scan error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/config')
def get_config():
    """Get current configuration (sanitized)"""
    safe_config = {
        'network': config.get('network', {}),
        'automation_level': config.get('automation_level', 1)
    }
    # Remove sensitive data
    safe_config['network'].pop('exclude_ips', None)

    return jsonify(safe_config)


@app.route('/api/config/update', methods=['POST'])
def update_config():
    """Update configuration"""
    try:
        data = request.get_json()

        # Update config
        if 'network' in data:
            config['network'].update(data['network'])

        # Save to file
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config, f)

        return jsonify({'status': 'success', 'message': 'Configuration updated'})

    except Exception as e:
        logger.error(f"Config update error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    try:
        # Host statistics
        total_hosts = len(scan_results)
        hosts_by_type = {}
        hosts_by_os = {}

        for host in scan_results:
            # Count by device type
            device_type = host.get('device_type', 'unknown')
            hosts_by_type[device_type] = hosts_by_type.get(device_type, 0) + 1

            # Count by OS
            os_guess = host.get('os_guess', 'Unknown')
            hosts_by_os[os_guess] = hosts_by_os.get(os_guess, 0) + 1

        # Scan history
        scan_files = sorted(DATA_DIR.glob('scan_*.json'), reverse=True)
        recent_scans = []
        for scan_file in scan_files[:10]:  # Last 10 scans
            try:
                with open(scan_file, 'r') as f:
                    data = json.load(f)
                    recent_scans.append({
                        'timestamp': data.get('scan_time'),
                        'hosts_found': data.get('total_hosts', 0)
                    })
            except:
                pass

        return jsonify({
            'total_hosts': total_hosts,
            'hosts_by_type': hosts_by_type,
            'hosts_by_os': hosts_by_os,
            'recent_scans': recent_scans,
            'last_scan': recent_scans[0]['timestamp'] if recent_scans else None
        })

    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'scanner_ready': scanner is not None,
        'timestamp': datetime.now().isoformat()
    })


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500


# Initialize on startup
load_config()
init_scanner()

# Auto-load latest scan results on startup
if scanner:
    latest = scanner.load_latest_scan()
    if latest:
        scan_results = latest.get('hosts', [])
        logger.info(f"Loaded {len(scan_results)} hosts from previous scan")

if __name__ == '__main__':
    port = config.get('dashboard', {}).get('port', 8080)
    host = config.get('dashboard', {}).get('host', '0.0.0.0')

    logger.info(f"Starting dashboard on {host}:{port}")
    app.run(host=host, port=port, debug=False)