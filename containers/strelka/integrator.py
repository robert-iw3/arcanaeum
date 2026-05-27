import json
import os
import shutil
import time

EVE_JSON = '/suricata-logs/eve.json'
FILE_STORE = '/suricata-files'
DROP_DIR = '/file-drop'
STRELKA_HOST = os.getenv('STRELKA_HOST', 'frontend:8732')

def tail_file(file_path):
    with open(file_path, 'r') as f:
        f.seek(0, 2)  # Go to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

for line in tail_file(EVE_JSON):
    try:
        event = json.loads(line)
        if event.get('event_type') == 'alert' and 'fileinfo' in event:
            file_hash = event['fileinfo']['sha256']
            file_path = os.path.join(FILE_STORE, file_hash)
            if os.path.exists(file_path):
                dest_path = os.path.join(DROP_DIR, os.path.basename(event['fileinfo']['filename']))
                shutil.copy(file_path, dest_path)
                print(f"Triggered Strelka scan for {dest_path}")
    except json.JSONDecodeError:
        pass