import os
import re
import json
import glob
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load configuration
CONFIG_PATH = os.getenv('CONFIG_PATH', './config.json')
try:
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    logger.warning(f"Config file {CONFIG_PATH} not found, using defaults.")
    CONFIG = {
        "comment_patterns": [
            {"pattern": "^\\s*--\\s*(.*)$", "extractor": "group(1)"},
            {"pattern": "^\\s*#\\s*(.*)$", "extractor": "group(1)"},
            {"pattern": "^\\s*//\\s*(.*)$", "extractor": "group(1)"},
            {"pattern": "^\\s*`#\\s*(.*?)\\s*#`\\s*$", "extractor": "group(1)"},
            {"pattern": "^\\s*`comment\\(\\s*--\\s*(.*?)\\s*\\)`\\s*$", "extractor": "group(1)"},
            {"pattern": "^\\s*/\\*\\s*(.*?)\\s*\\*/\\s*$", "extractor": "group(1)"}
        ],
        "validation_rules": {
            "required_metadata": ["title"],
            "allowed_spl_commands": ["search", "table", "stats", "eval", "where", "fields", "tstats", "inputlookup"],
            "allow_macros": true,
            "validate_macro_arguments": true,
            "allow_subsearches": true
        },
        "normalization_rules": {
            "standardize_case": true,
            "normalize_whitespace": true
        },
        "custom_cim_mappings": {}
    }

# Default CIM field mappings
CIM_FIELD_MAPPINGS = {
    'username': 'user',
    'source_ip': 'src_ip',
    'destination_ip': 'dest_ip',
    'login_status': 'action',
    'source': 'src',
    'destination': 'dest',
    'source_port': 'src_port',
    'destination_port': 'dest_port',
    'protocol': 'transport',
    'bytes_in': 'bytes_in',
    'bytes_out': 'bytes_out',
    'signature_id': 'signature',
    'severity_id': 'severity',
    'ids_category': 'category',
    'method': 'http_method',
    'url': 'url',
    'status_code': 'status',
    'user_agent': 'http_user_agent',
    'process_name': 'process',
    'file_path': 'file_path',
    'parent_process': 'parent_process',
    'command_line': 'process'
}
CIM_FIELD_MAPPINGS.update(CONFIG.get('custom_cim_mappings', {}))

def map_to_cim_fields(query, custom_mappings=None):
    """
    Maps non-CIM-compliant fields to CIM-compliant fields.
    """
    if not query:
        return query
    mappings = CIM_FIELD_MAPPINGS.copy()
    if custom_mappings:
        mappings.update(custom_mappings)
        logger.info(f"Applied custom CIM mappings: {custom_mappings}")
    modified_query = query
    for non_cim, cim in mappings.items():
        pattern = re.compile(r'\b' + re.escape(non_cim) + r'\b', re.IGNORECASE)
        if pattern.search(modified_query):
            modified_query = pattern.sub(cim, modified_query)
            logger.info(f"Mapped field '{non_cim}' to CIM-compliant '{cim}' in query")
    return modified_query

def normalize_query(query):
    """
    Normalizes Splunk query based on config.json rules.
    """
    if not query:
        return query
    normalized_query = query
    if CONFIG['normalization_rules'].get('standardize_case', True):
        commands = CONFIG['validation_rules'].get('allowed_spl_commands', [])
        for cmd in commands:
            pattern = re.compile(r'\b' + re.escape(cmd) + r'\b', re.IGNORECASE)
            normalized_query = pattern.sub(cmd.lower(), normalized_query)
        logger.info(f"Standardized case for commands: {commands}")
    if CONFIG['normalization_rules'].get('normalize_whitespace', True):
        normalized_query = re.sub(r'\s+', ' ', normalized_query)
        normalized_query = re.sub(r'\|\s*\|+', '|', normalized_query).strip()
        logger.info("Normalized whitespace and removed redundant pipes")
    return normalized_query

def correct_query_syntax(query):
    """
    Corrects common Splunk SPL syntax errors, including complex macros.
    """
    if not query:
        return query
    corrected_query = normalize_query(query.strip())

    if not corrected_query.startswith(('search ', '|', 'index=', '`', 'tstats ', 'inputlookup ')):
        corrected_query = f"search {corrected_query}"
        logger.info("Added missing 'search' keyword to query")

    commands = CONFIG['validation_rules'].get('allowed_spl_commands', [])
    for cmd in commands:
        pattern = re.compile(r'\b' + cmd + r'\b(?!\s*\|\s*)', re.IGNORECASE)
        if pattern.search(corrected_query):
            corrected_query = pattern.sub(f'| {cmd}', corrected_query)
            logger.info(f"Added missing pipe before '{cmd}' command")

    quote_count = corrected_query.count('"')
    if quote_count % 2 != 0:
        corrected_query += '"'
        logger.info("Added missing closing quote to query")

    open_paren = corrected_query.count('(')
    close_paren = corrected_query.count(')')
    if open_paren > close_paren:
        corrected_query += ')' * (open_paren - close_paren)
        logger.info(f"Added {open_paren - close_paren} missing closing parentheses")
    elif close_paren > open_paren:
        corrected_query = '(' * (close_paren - open_paren) + corrected_query
        logger.info(f"Added {close_paren - open_paren} missing opening parentheses")

    if CONFIG['validation_rules'].get('allow_macros', True):
        macro_pattern = re.compile(r'\b([a-zA-Z0-9_]+)(\([^\)]*\))?\b(?<!`)', re.IGNORECASE)
        corrected_query = macro_pattern.sub(r'`\1\2`', corrected_query)
        logger.info("Added backticks to macro references")

    return corrected_query

def parse_metadata_and_search(block):
    """
    Parses metadata from SQL block comments and separates the search query.
    """
    lines = block.split('\n')
    metadata = {}
    custom_mappings = {}
    search_lines = []
    i = 0
    in_desc = False
    desc_lines = []

    comment_patterns = [
        (re.compile(p['pattern'], re.MULTILINE), lambda m, extractor=p['extractor']: m.group(int(extractor.replace('group(', '').replace(')', ''))))
        for p in CONFIG['comment_patterns']
    ]

    while i < len(lines):
        line = lines[i].strip()
        is_comment = False
        comment_content = None

        for pattern, extractor in comment_patterns:
            match = pattern.match(line)
            if match:
                is_comment = True
                comment_content = extractor(match)
                logger.debug(f"Detected comment style in line: {line}")
                break

        if line.startswith('`comment(') and not is_comment:
            is_comment = True
            comment_block = []
            j = i
            while j < len(lines) and not lines[j].strip().endswith(')`'):
                comment_block.append(lines[j].strip())
                j += 1
            if j < len(lines):
                comment_block.append(lines[j].strip())
                i = j
            comment_text = '\n'.join(comment_block)[9:-2].strip()
            inner_lines = comment_text.split('\n')
            for inner in inner_lines:
                inner_strip = inner.strip()
                for pattern, extractor in comment_patterns:
                    match = pattern.match(inner_strip)
                    if match:
                        comment_content = extractor(match)
                        break
                if comment_content:
                    if ':' in comment_content:
                        k, v = comment_content.split(':', 1)
                        k = k.strip().lower()
                        v = v.strip()
                        if k == 'description' and v == '>':
                            in_desc = True
                            desc_lines = []
                        elif k == 'field_map' and '=' in v:
                            old_field, new_field = v.split('=', 1)
                            custom_mappings[old_field.strip()] = new_field.strip()
                        elif in_desc:
                            desc_lines.append(v)
                        else:
                            metadata[k] = v
                    elif in_desc and inner_strip:
                        desc_lines.append(inner_strip)
                comment_content = None
            if in_desc:
                metadata['description'] = '\n'.join(desc_lines).strip()
                in_desc = False

        elif line.startswith('`#') and not is_comment:
            is_comment = True
            comment_text = line[2:].rstrip('#`').strip()
            lines_text = comment_text.split('\n')
            for cl in lines_text:
                cl_strip = cl.strip()
                for pattern, extractor in comment_patterns:
                    match = pattern.match(cl_strip)
                    if match:
                        comment_content = extractor(match)
                        break
                if comment_content:
                    if ':' in comment_content:
                        k, v = comment_content.split(':', 1)
                        k = k.strip().lower()
                        v = v.strip()
                        if k == 'description' and v == '>':
                            in_desc = True
                            desc_lines = []
                        elif k == 'field_map' and '=' in v:
                            old_field, new_field = v.split('=', 1)
                            custom_mappings[old_field.strip()] = new_field.strip()
                        elif in_desc:
                            desc_lines.append(v)
                        else:
                            metadata[k] = v
                    elif in_desc and cl_strip:
                        desc_lines.append(cl_strip)
                comment_content = None
            if in_desc:
                metadata['description'] = '\n'.join(desc_lines).strip()
                in_desc = False

        elif comment_content:
            is_comment = True
            if ':' in comment_content:
                k, v = comment_content.split(':', 1)
                k = k.strip().lower()
                v = v.strip()
                if k == 'description' and v == '>':
                    in_desc = True
                    desc_lines = []
                elif k == 'field_map' and '=' in v:
                    old_field, new_field = v.split('=', 1)
                    custom_mappings[old_field.strip()] = new_field.strip()
                elif in_desc:
                    desc_lines.append(v)
                else:
                    metadata[k] = v
            elif in_desc and comment_content:
                desc_lines.append(comment_content)

        if in_desc and not is_comment:
            if line:
                desc_lines.append(line.strip())
            else:
                metadata['description'] = '\n'.join(desc_lines).strip()
                in_desc = False

        if not is_comment:
            search_lines.append(lines[i])

        i += 1

    if in_desc:
        metadata['description'] = '\n'.join(desc_lines).strip()

    for field in CONFIG['validation_rules'].get('required_metadata', []):
        if field not in metadata:
            logger.warning(f"Missing required metadata '{field}' in query block")
            metadata[field] = f"Missing_{field}"

    search = '\n'.join([l.rstrip() for l in search_lines if l.strip()]).strip()
    return metadata, correct_query_syntax(map_to_cim_fields(search, custom_mappings)), custom_mappings

def extract_queries_from_md(md_content, md_filename):
    """
    Extracts SQL queries and metadata from a Markdown file.
    """
    queries = []
    try:
        sections = re.split(r'^###+\s*(.+)$', md_content, flags=re.MULTILINE)
        if len(sections) == 1:
            sections = ['', md_content]

        for i in range(1, len(sections), 2):
            title = sections[i].strip()
            content = sections[i+1]
            desc_match = re.search(r'^(.*?)(?:\n\s*```sql\b|$)', content, re.DOTALL | re.MULTILINE)
            section_desc = ''
            if desc_match:
                section_desc = re.sub(r'^---\s*\n?', '', desc_match.group(1)).strip()

            code_blocks = re.findall(r'```sql\s*?\n(.*?)(?:\n\s*```|$)', content, re.DOTALL | re.MULTILINE)
            if not code_blocks:
                logger.warning(f"No valid SQL code blocks found in section '{title}' of {md_filename}")
                continue

            for j, block in enumerate(code_blocks):
                if not block.strip():
                    logger.warning(f"Empty SQL block in section '{title}' of {md_filename}")
                    continue
                metadata, search, custom_mappings = parse_metadata_and_search(block)
                name = metadata.get('title', metadata.get('rule title', title or f"Untitled_{j+1}"))
                description = metadata.get('description', section_desc)
                extra = []
                for field in ['author', 'date', 'falsepositives', 'level', 'tags']:
                    if field in metadata:
                        extra.append(f"{field.capitalize()}: {metadata[field]}")
                if extra:
                    description += '\n\n' + '\n'.join(extra)
                query_data = {
                    "name": name,
                    "search": search,
                    "description": description,
                    "is_scheduled": 1,
                    "disabled": 0,
                    "cron_schedule": "*/30 * * * *",
                    "dispatch.earliest_time": "-24h",
                    "dispatch.latest_time": "now",
                    "sharing": "global",
                    "acl": {
                        "read": os.getenv('ACL_READ', 'power,admin').split(','),
                        "write": os.getenv('ACL_WRITE', 'admin').split(',')
                    }
                }
                if len(code_blocks) > 1:
                    query_data['name'] += f'_{j+1}'
                queries.append(query_data)
        return queries
    except Exception as e:
        logger.error(f"Error processing {md_filename}: {e}")
        return []

def save_to_json(queries, output_dir, md_path):
    """
    Saves extracted queries to JSON files.
    """
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        path_prefix = re.sub(r'[^a-zA-Z0-9_]', '_', os.path.dirname(md_path).replace(os.sep, '_'))
        if path_prefix:
            path_prefix += '_'
        for query in queries:
            safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', query['name'].lower().replace(' ', '_'))
            filename = f"{path_prefix}{safe_name}.json"
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump([query], f, indent=4)
            logger.info(f"Saved {filename} from query '{query['name']}' in {md_path}")
    except Exception as e:
        logger.error(f"Error saving JSON files for {md_path}: {e}")

if __name__ == "__main__":
    output_dir = './import/searches'
    md_files = sorted(glob.glob('**/*.md', recursive=True))

    if not md_files:
        logger.error("No Markdown files found in current directory or subdirectories.")
        exit(1)

    max_files = int(os.getenv('MAX_FILES', 1000))
    md_files = md_files[:max_files]
    logger.info(f"Found {len(md_files)} Markdown files (limited to {max_files}) in current directory and subdirectories.")
    for md_path in md_files:
        logger.info(f"Processing {md_path}")
        try:
            with open(md_path, 'r', encoding='utf-8') as f:
                md_content = f.read()
            queries = extract_queries_from_md(md_content, md_path)
            save_to_json(queries, output_dir, md_path)
        except Exception as e:
            logger.error(f"Failed to process {md_path}: {e}")
            continue

    logger.info("Markdown processing complete.")