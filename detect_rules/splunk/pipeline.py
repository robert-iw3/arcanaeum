import os
import json
import logging
import multiprocessing as mp
from pathlib import Path
import glob
import re
from jsonschema import validate_json
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from md_to_json import extract_queries_from_md, CONFIG
from import_searches import get_session_key, import_searches_from_file, validate_query_api, validate_saved_search_api

"""
# Simple JSON schema validation function
def validate_json(data):
    try:
        validate(instance=data, schema=JSON_SCHEMA)
        return True
    except ValidationError as e:
        logger.warning(f"JSON schema validation error: {e}")
        return False
"""

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# JSON Schema for validation
JSON_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "search": {"type": "string"},
            "description": {"type": "string"},
            "is_scheduled": {"type": "integer", "enum": [0, 1]},
            "disabled": {"type": "integer", "enum": [0, 1]},
            "cron_schedule": {"type": "string"},
            "dispatch.earliest_time": {"type": "string"},
            "dispatch.latest_time": {"type": "string"},
            "sharing": {"type": "string"},
            "acl": {
                "type": "object",
                "properties": {
                    "read": {"type": "array", "items": {"type": "string"}},
                    "write": {"type": "array", "items": {"type": "string"}}
                }
            }
        },
        "required": ["name", "search"]
    }
}

def get_macro_definitions(session):
    """
    Retrieves macro definitions from Splunk.
    Returns a dictionary of macro names to their argument counts.
    """
    macros_url = f"https://{os.getenv('SPLUNK_HOST', 'localhost')}:{os.getenv('SPLUNK_PORT', '8089')}/servicesNS/-/-/configs/conf-macros"
    try:
        response = session.get(macros_url, verify=os.getenv('SPLUNK_SSL_VERIFY', 'true').lower() == 'true', timeout=int(os.getenv('API_TIMEOUT', 10)))
        response.raise_for_status()
        macros = response.json().get('entry', [])
        macro_defs = {}
        for macro in macros:
            name = macro['name']
            content = macro.get('content', {})
            args = content.get('definition', '').split('|')[0].count(',')
            macro_defs[name] = args + 1 if args > 0 else 0
        logger.info(f"Retrieved {len(macro_defs)} macro definitions")
        return macro_defs
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to retrieve macro definitions: {e}")
        return {}

def validate_splunk_query(query, session=None):
    """
    Validates Splunk SPL syntax using multiple API endpoints and macro validation.
    """
    if not query.strip():
        return False
    VALIDATE_API = os.getenv('VALIDATE_API', 'true').lower() == 'true'

    # Basic validation
    valid_starts = ('search ', '|', 'index=', '`', 'tstats ', 'inputlookup ')
    basic_valid = any(query.strip().startswith(start) for start in valid_starts)

    if not VALIDATE_API or not session:
        return basic_valid

    # Validate via /services/search/validate
    if not validate_query_api(query, session):
        logger.warning(f"Query failed /services/search/validate: {query[:50]}...")
        return False

    # Validate via /services/search/parser
    parser_url = f"https://{os.getenv('SPLUNK_HOST', 'localhost')}:{os.getenv('SPLUNK_PORT', '8089')}/services/search/parser"
    try:
        response = session.post(parser_url, data={"q": query, "parse_only": "true"}, verify=os.getenv('SPLUNK_SSL_VERIFY', 'true').lower() == 'true', timeout=int(os.getenv('API_TIMEOUT', 10)))
        response.raise_for_status()
        parser_result = response.json()
        if parser_result.get('status') != 'success':
            logger.warning(f"Query parsing failed: {query[:50]}... - {parser_result.get('messages', 'Unknown error')}")
            return False
        commands = parser_result.get('commands', [])
        allowed_commands = CONFIG['validation_rules'].get('allowed_spl_commands', [])
        for cmd in commands:
            if allowed_commands and cmd.get('command') not in [c.lower() for c in allowed_commands]:
                logger.warning(f"Query contains disallowed command '{cmd.get('command')}'")
                return False
        if not CONFIG['validation_rules'].get('allow_macros', True) and any(cmd.get('type') == 'macro' for cmd in commands):
            logger.warning("Query contains macros, which are not allowed by config")
            return False
        if not CONFIG['validation_rules'].get('allow_subsearches', True) and 'subsearch' in query:
            logger.warning("Query contains subsearches, which are not allowed by config")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Parser API failed for query: {query[:50]}... - {e}")
        return basic_valid

    # Validate macro arguments
    if CONFIG['validation_rules'].get('validate_macro_arguments', True) and CONFIG['validation_rules'].get('allow_macros', True):
        macro_defs = get_macro_definitions(session)
        macro_pattern = re.compile(r'`([a-zA-Z0-9_]+)(\([^)]*\))?`', re.IGNORECASE)
        for match in macro_pattern.finditer(query):
            macro_name = match.group(1)
            args = match.group(2) or ''
            arg_count = len([a for a in args.strip('()').split(',') if a.strip()]) if args else 0
            expected_args = macro_defs.get(macro_name, -1)
            if expected_args == -1:
                logger.warning(f"Macro '{macro_name}' not found in Splunk definitions")
                return False
            if expected_args != arg_count:
                logger.warning(f"Macro '{macro_name}' expects {expected_args} arguments, got {arg_count}")
                return False
        logger.info(f"Macro arguments validated for query: {query[:50]}...")

    return True

def process_md_file(md_path, output_dir, session=None):
    """
    Worker function for parallel processing: Convert single MD to JSON.
    """
    try:
        with open(md_path, 'r', encoding='utf-8') as f:
            md_content = f.read()
        queries = extract_queries_from_md(md_content, md_path)
        temp_json_files = []
        for query in queries:
            if not validate_splunk_query(query.get('search', ''), session):
                logger.warning(f"Invalid Splunk query in {md_path} for {query.get('name', 'unnamed')}")
                continue
            # Validate saved search configuration
            if session and os.getenv('VALIDATE_API', 'true').lower() == 'true':
                if not validate_saved_search_api(query, session):
                    logger.warning(f"Invalid saved search configuration in {md_path} for {query.get('name', 'unnamed')}")
                    continue
            path_prefix = re.sub(r'[^a-zA-Z0-9_]', '_', os.path.dirname(md_path).replace(os.sep, '_'))
            if path_prefix:
                path_prefix += '_'
            safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', query['name'].lower().replace(' ', '_'))
            temp_path = Path(output_dir) / f"{path_prefix}{safe_name}_temp.json"
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump([query], f, indent=4)
            if validate_json([query]):
                final_path = Path(output_dir) / f"{path_prefix}{safe_name}.json"
                os.rename(temp_path, final_path)
                temp_json_files.append(str(final_path))
                logger.info(f"Generated JSON {final_path} from {md_path}")
            else:
                os.remove(temp_path)
        return temp_json_files
    except Exception as e:
        logger.error(f"Failed to process {md_path}: {e}")
        return []

def run_pipeline(dry_run=False):
    """
    Runs the pipeline: converts MD to JSON and imports to Splunk.
    """
    output_dir = './import/searches'
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    src_dir = '/import/src' if os.path.exists('/import/src') else '.'
    md_files = sorted(glob.glob(f'{src_dir}/**/*.md', recursive=True))
    max_files = int(os.getenv('MAX_FILES', 1000))
    md_files = md_files[:max_files]
    if not md_files:
        logger.error(f"No Markdown files found in {src_dir} or subdirectories.")
        return

    logger.info(f"Found {len(md_files)} Markdown files (limited to {max_files}) in {src_dir} and subdirectories.")

    session = None
    VALIDATE_API = os.getenv('VALIDATE_API', 'true').lower() == 'true'
    if VALIDATE_API and not dry_run:
        session_key = get_session_key()
        if session_key:
            session = requests.Session()
            session.headers.update({"Authorization": f"Splunk {session_key}"})
            retries = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504])
            session.mount('https://', HTTPAdapter(max_retries=retries))
        else:
            logger.warning("API validation disabled due to authentication failure. Using basic validation.")

    pool_size = int(os.getenv('POOL_SIZE', mp.cpu_count()))
    with mp.Pool(processes=pool_size) as pool:
        results = pool.starmap(process_md_file, [(md, output_dir, session) for md in md_files])
    json_files = [f for sublist in results for f in sublist]

    if not json_files:
        logger.error("No JSON files generated from Markdown files.")
        return

    if dry_run:
        logger.info("Dry-run mode: Skipping API import.")
        for j in json_files:
            with open(j, 'r', encoding='utf-8') as f:
                queries = json.load(f)
                for q in queries:
                    logger.info(f"Would import: {q['name']} from {j}")
        return

    if not session:
        session_key = get_session_key()
        if not session_key:
            logger.error("Failed to authenticate with Splunk.")
            return
        session = requests.Session()
        session.headers.update({"Authorization": f"Splunk {session_key}"})
        retries = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))

    for file in json_files:
        import_searches_from_file(file, session_key, session)
        if os.getenv('CLEANUP_JSON', 'false').lower() == 'true':
            os.remove(file)
            logger.info(f"Removed temporary JSON file: {file}")

if __name__ == "__main__":
    import sys
    dry_run = '--dry-run' in sys.argv
    run_pipeline(dry_run)