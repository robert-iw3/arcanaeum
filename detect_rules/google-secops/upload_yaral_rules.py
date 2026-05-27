# pip install google-auth requests

"""
    How to use the script

    Download your service account key file from Google Cloud and place in this directory.

    In the Dockerfile:

    Update the CHRONICLE_API_URL to match your Google Security Operations instance.

    podman build -t yara-l-upload .
    podman run -it --name yara-l-upload -d yara-l-upload
    podman stop yara-l-upload
    podman system prune -f

"""
import os
import requests
import urllib3
from google.oauth2 import service_account
import glob
import google.auth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---

CHRONICLE_API_URL = os.getenv('CHRONICLE_API_URL')
CREDENTIALS_FILE = os.getenv('CREDENTIALS_FILE')
AUTH_SCOPE = os.getenv('AUTH_SCOPE')

# --- Authentication ---
def get_auth_headers():
    """Generates authentication headers using the service account."""
    try:
        credentials = service_account.Credentials.from_service_account_file(
            CREDENTIALS_FILE,
            scopes=[AUTH_SCOPE]
        )
        auth_request = google.auth.transport.requests.Request()
        credentials.refresh(auth_request)
        access_token = credentials.token
        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
    except Exception as e:
        print(f"Authentication failed: {e}")
        return None

# --- File Discovery and Upload ---
def find_yaral_files(directory="."):
    """Finds all .yaral files recursively in a given directory."""
    return glob.glob(os.path.join(directory, "**", "*.yaral"), recursive=True)

def upload_yaral_rule(headers, rule_content):
    """Uploads a single YARA-L rule to the API."""
    url = f"{CHRONICLE_API_URL}/rules"
    payload = {
        "ruleText": rule_content
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        print(f"Rule uploaded successfully: {response.json().get('ruleId')}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to upload rule: {e}")
        if e.response:
            print(f"Response content: {e.response.text}")

def main(directory="."):
    """Main function to find and upload all YARA-L files."""
    headers = get_auth_headers()
    if not headers:
        return

    yaral_files = find_yaral_files(directory)
    if not yaral_files:
        print(f"No .yaral files found in directory: {directory}")
        return

    for file_path in yaral_files:
        print(f"Processing file: {file_path}")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_content = f.read()
            upload_yaral_rule(headers, rule_content)
        except Exception as e:
            print(f"Could not read file {file_path}: {e}")

if __name__ == "__main__":
    # Specify the directory to start searching from
    target_directory = "."
    main(target_directory)
