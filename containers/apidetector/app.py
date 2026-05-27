from flask import Flask, render_template, request, jsonify, send_file, Response
import concurrent.futures
import os
import sys
import asyncio
import json
import tempfile
import argparse
import re
import time
import uuid
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add the current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

import apidetectorv2
import pocgenerator

common_endpoints = [
    '/swagger-ui.html', '/openapi.json', '/v2/api-docs', '/v3/api-docs',
    # ... (keeping the full list unchanged for brevity)
]

app = Flask(__name__)

# Global dictionary to track active scans
active_scans = {}

SCREENSHOTS_FOLDER = os.path.join(current_dir, 'screenshots')
UPLOADS_FOLDER = os.path.join(current_dir, 'uploads')
os.makedirs(SCREENSHOTS_FOLDER, exist_ok=True)
os.makedirs(UPLOADS_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOADS_FOLDER
app.config['SCREENSHOTS_FOLDER'] = SCREENSHOTS_FOLDER

def validate_domain(domain):
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'
    )
    return bool(domain_pattern.match(domain))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json() if request.is_json else request.form
        domain = data.get('domain', '').strip()
        domains = [domain] if domain else []

        if 'domainFile' in request.files:
            domain_file = request.files['domainFile']
            if domain_file.filename:
                content = domain_file.read().decode('utf-8')
                domains.extend(line.strip() for line in content.splitlines() if line.strip())

        valid_domains = [d for d in domains if validate_domain(d)]
        if not valid_domains:
            return jsonify({'error': 'No valid domains provided'}), 400

        scan_id = str(uuid.uuid4())
        active_scans[scan_id] = {
            'domains': valid_domains,
            'results': [],
            'status': 'running',
            'current_domain': '',
            'progress': 0,
            'start_time': time.time()
        }

        def run_scan():
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(valid_domains), 20)) as executor:
                    futures = []
                    for domain in valid_domains:
                        active_scans[scan_id]['current_domain'] = domain
                        os.environ['SCREENSHOT_PATH'] = app.config['SCREENSHOTS_FOLDER']
                        futures.append(
                            executor.submit(
                                apidetectorv2.test_subdomain_endpoints,
                                domain,
                                common_endpoints,
                                data.get('mixedMode', False),
                                True,
                                data.get('userAgent', 'Mozilla/5.0')
                            )
                        )
                    for i, future in enumerate(concurrent.futures.as_completed(futures)):
                        results = future.result()
                        if results:
                            active_scans[scan_id]['results'].extend(results)
                        active_scans[scan_id]['progress'] = int(((i + 1) / len(futures)) * 100)
                active_scans[scan_id]['status'] = 'completed'
                active_scans[scan_id]['end_time'] = time.time()
            except Exception as e:
                logger.error(f"Scan error: {str(e)}")
                active_scans[scan_id]['status'] = 'error'
                active_scans[scan_id]['error'] = str(e)

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        executor.submit(run_scan)

        return jsonify({
            'scan_id': scan_id,
            'message': f'Scan started for {len(valid_domains)} domain(s)',
            'valid_domains': valid_domains
        })

    except Exception as e:
        logger.error(f"Scan initiation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/scan-status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    scan_data = active_scans[scan_id]
    return jsonify({
        'status': scan_data['status'],
        'progress': scan_data['progress'],
        'current_domain': scan_data['current_domain'],
        'results': scan_data['results'],
        'total_domains': len(scan_data['domains']),
        'domains_scanned': int((scan_data['progress'] / 100) * len(scan_data['domains']))
    })

@app.route('/screenshots/<path:filename>')
def serve_screenshot(filename):
    try:
        possible_paths = [
            os.path.join(app.config['SCREENSHOTS_FOLDER'], filename),
            os.path.join(app.config['SCREENSHOTS_FOLDER'], f"{''.join(c if c.isalnum() else '_' for c in filename)}.png")
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return send_file(path, mimetype='image/png')
        placeholder_path = os.path.join(current_dir, 'static', 'placeholder.png')
        return send_file(placeholder_path, mimetype='image/png') if os.path.exists(placeholder_path) else Response(
            'Screenshot not available', status=404, headers={'Content-Type': 'text/plain'})
    except Exception as e:
        logger.error(f"Screenshot error: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='APIDetector Web Interface')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Port to run on')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to run on')
    parser.add_argument('-d', '--debug', action='store_true', help='Run in debug mode')
    args = parser.parse_args()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    logger.info(f"Starting server at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)