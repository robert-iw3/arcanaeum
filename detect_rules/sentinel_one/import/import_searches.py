import os
import json
import requests
from pathlib import Path

# SentinelOne API configuration
API_TOKEN = os.getenv('API_TOKEN')
SENTINELONE_API_URL = os.getenv('SENTINELONE_API_URL')
API_VERSION = "v2.1"

HEADERS = {
    "Authorization": f"ApiToken {API_TOKEN}",
    "Content-Type": "application/json"
}

def get_json_files(directory):
    """Recursively find all .json files in the given directory and its subdirectories."""
    json_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".json"):
                json_files.append(os.path.join(root, file))
    return json_files

def read_json_file(file_path):
    """Read and parse a JSON file."""
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON in {file_path}: {e}")
        return None
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def import_to_sentinelone(json_data, endpoint):
    """Send JSON data to SentinelOne API endpoint."""
    if not API_TOKEN or not SENTINELONE_API_URL:
        print("API_TOKEN or SENTINELONE_API_URL is not set. Please check environment variables.")
        return False

    full_url = f"{SENTINELONE_API_URL}/web/api/{API_VERSION}/{endpoint}"

    try:
        response = requests.post(
            full_url,
            headers=HEADERS,
            json=json_data
        )
        response.raise_for_status() # Raise an exception for bad status codes

        response_json = response.json()
        if response.status_code in [200, 201]:
            print(f"Successfully initiated import to {endpoint}.")
            if response_json.get('data', {}).get('queryId'):
                print(f"Deep Visibility Query ID: {response_json['data']['queryId']}")
            return True
        else:
            print(f"Failed to import data to {endpoint}: {response.status_code} - {response.text}")
            return False

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error importing to {endpoint}: {e}")
        return False
    except requests.RequestException as e:
        print(f"Error sending data to {endpoint}: {e}")
        return False

def main():
    # Get the current directory
    current_dir = Path.cwd()
    print(f"Scanning for JSON files in {current_dir}...")

    # Find all JSON files
    json_files = get_json_files(current_dir)
    if not json_files:
        print("No JSON files found in the current directory or subdirectories.")
        return

    print(f"Found {len(json_files)} JSON files.")

    # Process each JSON file
    for file_path in json_files:
        print(f"\nProcessing {file_path}...")
        json_data = read_json_file(file_path)
        if json_data is None:
            continue

        endpoint = None
        # Determine the appropriate API endpoint based on JSON content
        # Check for Deep Visibility query structure first
        if "queryText" in json_data and json_data.get("queryType") == "events":
            endpoint = "deep-visibility/queries"
        # Example for other endpoints based on keys
        elif "threat" in json_data:
            endpoint = "threats"
        elif "policy" in json_data:
            endpoint = "policies"
        else:
            print(f"Unknown JSON structure in {file_path}. Skipping.")
            continue

        # Import the JSON data to SentinelOne
        import_to_sentinelone(json_data, endpoint)

if __name__ == "__main__":
    main()