import json
import requests
import urllib3
import glob
import os
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pathlib import Path
from ratelimit import limits, sleep_and_retry
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress InsecureRequestWarning if SSL verification is disabled
if os.getenv('SPLUNK_SSL_VERIFY', 'true').lower() != 'true':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = os.getenv('SPLUNK_PORT', '8089')
SPLUNK_USER = os.getenv('SPLUNK_USER', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD')
APP_CONTEXT = os.getenv('APP_CONTEXT', 'search')
SPLUNK_SSL_VERIFY = os.getenv('SPLUNK_SSL_VERIFY', 'true').lower() == 'true'
ACL_READ = os.getenv('ACL_READ', 'power,admin').split(',')
ACL_WRITE = os.getenv('ACL_WRITE', 'admin').split(',')
RATE_LIMIT_CALLS = int(os.getenv('RATE_LIMIT_CALLS', 10))
RATE_LIMIT_PERIOD = int(os.getenv('RATE_LIMIT_PERIOD', 60))
API_TIMEOUT = int(os.getenv('API_TIMEOUT', 10))
VALIDATE_API = os.getenv('VALIDATE_API', 'true').lower() == 'true'

def get_session_key():
    """
    Obtains a session key for authorization from Splunk.
    """
    auth_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/auth/login"
    payload = {"username": SPLUNK_USER, "password": SPLUNK_PASSWORD}
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    try:
        response = session.post(auth_url, data=payload, verify=SPLUNK_SSL_VERIFY, timeout=API_TIMEOUT)
        response.raise_for_status()
        session_key = response.text.split("<sessionkey>")[1].split("</sessionkey>")[0]
        logger.info("Successfully obtained Splunk session key.")
        return session_key
    except requests.exceptions.RequestException as e:
        logger.error(f"Authentication failed: {e}")
        return None

def validate_query_api(query, session):
    """
    Validates a Splunk query using /services/search/validate and /services/search/parser.
    """
    # Validate via /services/search/validate
    validate_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/validate"
    try:
        response = session.post(validate_url, data={"q": query}, verify=SPLUNK_SSL_VERIFY, timeout=API_TIMEOUT)
        response.raise_for_status()
        if "<valid>true</valid>" not in response.text:
            logger.warning(f"Query validation failed via /services/search/validate: {query[:50]}... - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Validate API failed for query: {query[:50]}... - {e}")
        return False

    # Validate via /services/search/parser
    parser_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/parser"
    try:
        response = session.post(parser_url, data={"q": query, "parse_only": "true"}, verify=SPLUNK_SSL_VERIFY, timeout=API_TIMEOUT)
        response.raise_for_status()
        parser_result = response.json()
        if parser_result.get('status') != 'success':
            logger.warning(f"Query parsing failed via /services/search/parser: {query[:50]}... - {parser_result.get('messages', 'Unknown error')}")
            return False
        logger.info(f"Query validated successfully via API: {query[:50]}...")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Parser API failed for query: {query[:50]}... - {e}")
        return False

def validate_saved_search_api(search_data, session):
    """
    Validates a saved search configuration using /services/saved/searches/validate.
    """
    validate_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/servicesNS/nobody/{APP_CONTEXT}/saved/searches/validate"
    prepared_data, _, _ = prepare_search_data(search_data)
    try:
        response = session.post(validate_url, data=prepared_data, verify=SPLUNK_SSL_VERIFY, timeout=API_TIMEOUT)
        response.raise_for_status()
        logger.info(f"Saved search configuration validated for {search_data.get('name', 'unnamed')}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Saved search validation failed for {search_data.get('name', 'unnamed')}: {e}")
        return False

def prepare_search_data(search_data):
    """
    Prepares search data for Splunk API.
    """
    prepared_data = search_data.copy()

    for key in ["disabled", "is_scheduled"]:
        if key in prepared_data:
            prepared_data[key] = '1' if prepared_data[key] else '0'

    sharing = prepared_data.pop("sharing", "app")
    acl = prepared_data.pop("acl", {"read": ACL_READ, "write": ACL_WRITE})

    return prepared_data, sharing, acl

def update_acl(search_name, session_key, session, sharing, acl):
    """
    Updates the ACL for a saved search in Splunk.
    """
    api_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/servicesNS/nobody/{APP_CONTEXT}/saved/searches/{search_name}/acl"
    data = {
        "sharing": sharing,
        "perms.read": ",".join(acl.get("read", [])),
        "perms.write": ",".join(acl.get("write", []))
    }
    try:
        response = session.post(api_url, data=data, verify=SPLUNK_SSL_VERIFY, timeout=API_TIMEOUT)
        response.raise_for_status()
        logger.info(f"Successfully updated ACL for {search_name} (sharing: {sharing})")
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error updating ACL for {search_name}: {e}")

@limits(calls=RATE_LIMIT_CALLS, period=RATE_LIMIT_PERIOD)
@sleep_and_retry
def api_call_wrapper(func, *args, **kwargs):
    """
    Wraps API calls with rate limiting and retry logic.
    """
    return func(*args, **kwargs)

def import_searches_from_file(file_path, session_key, session):
    """
    Imports searches from a JSON file into Splunk.
    """
    logger.info(f"Processing JSON file: {file_path}")
    try:
        with open(file_path, "r", encoding='utf-8') as f:
            searches = json.load(f)

        if not isinstance(searches, list):
            logger.error(f"Expected a list in {file_path}, skipping.")
            return

        for search_entry in searches:
            if "name" not in search_entry or "search" not in search_entry:
                logger.warning(f"Skipping entry in {file_path} due to missing 'name' or 'search'.")
                continue

            search_name = search_entry.pop("name")
            search_query = search_entry.get("search")

            if VALIDATE_API:
                if not api_call_wrapper(validate_query_api, search_query, session):
                    logger.warning(f"Skipping invalid query '{search_name}' in {file_path} after API validation.")
                    continue
                if not api_call_wrapper(validate_saved_search_api, search_entry, session):
                    logger.warning(f"Skipping invalid saved search configuration '{search_name}' in {file_path}.")
                    continue

            prepared_data, sharing, acl = prepare_search_data(search_entry)
            base_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/servicesNS/nobody/{APP_CONTEXT}/saved/searches"
            api_url = f"{base_url}/{search_name}"

            def make_api_call():
                response = session.get(api_url, verify=SPLUNK_SSL_VERIFY, timeout=API_TIMEOUT)
                if response.status_code == 200:
                    logger.info(f"Updating existing saved search: {search_name} from {file_path}")
                    return session.post(api_url, data=prepared_data, verify=SPLUNK_SSL_VERIFY, timeout=API_TIMEOUT)
                else:
                    logger.info(f"Creating new saved search: {search_name} from {file_path}")
                    payload = {"name": search_name, **prepared_data}
                    return session.post(base_url, data=payload, verify=SPLUNK_SSL_VERIFY, timeout=API_TIMEOUT)

            response = api_call_wrapper(make_api_call)
            if response.status_code in [200, 201]:
                logger.info(f"Successfully configured saved search: {search_name}")
                api_call_wrapper(update_acl, search_name, session_key, session, sharing, acl)
            else:
                logger.error(f"Failed to configure {search_name} from {file_path}: Status {response.status_code} - {response.text}")

    except FileNotFoundError:
        logger.error(f"JSON file not found: {file_path}")
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON format in file: {file_path}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error processing {file_path}: {e}")

if __name__ == "__main__":
    session_key = get_session_key()
    if not session_key:
        logger.error("Failed to get session key. Exiting.")
        exit(1)

    headers = {"Authorization": f"Splunk {session_key}"}
    session = requests.Session()
    session.headers.update(headers)
    retries = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))

    json_files = sorted(glob.glob('import/searches/**/*.json', recursive=True))
    if not json_files:
        logger.error("No JSON files found in ./import/searches.")
        exit(1)

    logger.info(f"Found {len(json_files)} JSON files in ./import/searches.")
    for file in json_files:
        import_searches_from_file(file, session_key, session)