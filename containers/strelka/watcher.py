import os
import json
import time
import requests
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from strelka.client import Client

DROP_DIR = '/file-drop'
SCAN_LOGS = '/scan-logs'
STRELKA_HOST = os.getenv('STRELKA_HOST', 'frontend:8732')
SIEM_TYPE = os.getenv('SIEM_TYPE', 'elastic')
SIEM_URL = os.getenv('SIEM_URL')
INDEX_NAME = os.getenv('INDEX_NAME', 'strelka-scans')

# Read secret
with open(os.getenv('SIEM_TOKEN_FILE', '/run/secrets/siem_token'), 'r') as f:
    SIEM_TOKEN = f.read().strip()

client = Client(f"{STRELKA_HOST}")

class Handler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            full_path = event.src_path
            try:
                scan_result = client.scan_file(full_path)
                scan_json = json.dumps(scan_result)
                # Transform to SIEM schema
                transformed = {}
                if SIEM_TYPE == 'splunk':
                    transformed = {
                        'sourcetype': 'strelka:scan',
                        'event': {
                            'source': scan_result.get('filename'),
                            'action': 'blocked' if scan_result.get('scan', {}).get('yara', {}).get('matches') else 'allowed',
                            'signature': scan_result.get('scan', {}).get('yara', {}).get('matches', []),
                            'file_hash_sha256': scan_result.get('scan', {}).get('hash', {}).get('sha256'),
                            'vendor_product': 'Strelka'
                        }
                    }
                    headers = {'Authorization': f'Splunk {SIEM_TOKEN}'}
                    requests.post(SIEM_URL, json=transformed, headers=headers)
                elif SIEM_TYPE == 'elastic':
                    transformed = {
                        '@timestamp': scan_result.get('time'),
                        'event': {'category': 'file', 'kind': 'event', 'module': 'strelka'},
                        'file': {'name': scan_result.get('filename'), 'hash': {'sha256': scan_result.get('scan', {}).get('hash', {}).get('sha256')}},
                        'threat': {'indicator': {'type': 'file', 'yara_matches': scan_result.get('scan', {}).get('yara', {}).get('matches', [])}}
                    }
                    headers = {'Content-Type': 'application/json'}
                    auth = ('elastic', SIEM_TOKEN) if 'elastic' in SIEM_URL else None
                    requests.post(f"{SIEM_URL}/{INDEX_NAME}/_doc/", json=transformed, headers=headers, auth=auth)
                # Log
                with open(f"{SCAN_LOGS}/strelka-{int(time.time())}.json", 'w') as f:
                    json.dump(transformed, f)

                # Quarantine/delete logic
                yara_matches = scan_result.get('scan', {}).get('yara', {}).get('matches', [])
                if yara_matches:
                    # Malicious → quarantine
                    quarantine_path = f"/quarantine/{os.path.basename(full_path)}"
                    try:
                        shutil.move(full_path, quarantine_path)
                    except Exception as move_err:
                        print(f"Error moving to quarantine: {move_err}")
                    # Optional: add extra SIEM field for "quarantined"
                else:
                    # Clean → delete
                    try:
                        os.remove(full_path)
                    except Exception as del_err:
                        print(f"Error deleting file: {del_err}")

            except Exception as e:
                print(f"Error: {e}")

observer = Observer()
observer.schedule(Handler(), DROP_DIR, recursive=False)
observer.start()
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()
observer.join()