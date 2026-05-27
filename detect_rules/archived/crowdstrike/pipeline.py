import os
import re
import json
import argparse
from typing import List, Dict, Optional
import logging
import yaml
from falconpy import CustomIOA
import time

logging.basicConfig(level='INFO', format='%(asctime)s - %(levelname)s - %(message)s')

# Supported FQL fields (from CrowdStrike docs)
SUPPORTED_FIELDS = {
    'event_simpleName', 'FileName', 'CommandLine', 'ParentBaseFileName', 'TargetFileName', 'RegistryKeyPath',
    'RegistryValue', 'DomainName', 'RemoteAddressIP4', 'RemotePort', 'ImageFileName', 'ParentCommandLine',
    'RegistryPath', 'RegistryValueData', 'TargetFilePath', 'LoadedImageName', 'LoadedImagePath', 'event_type',
    'resource_type', 'verb', 'k8s_pod_name', 'container_name', 'process_path', 'file_path', 'process_name',
    'parent_process_name', 'LocalAddress', 'RemoteAddress', 'BaseFileName', 'FilePath', 'SHA256HashData',
    'QueryName', 'TargetAddress', 'SourceAddress', 'ProcessName', 'ContainerId', 'eventName', 'userAgent',
    'userIdentity_arn', 'sourceIPAddress', 'eventSource', 'requestParameters_target', 'requestParameters_instanceIds',
    'requestParameters_documentName', 'requestParameters_parameters_commands', 'protoPayload_serviceName',
    'protoPayload_methodName', 'protoPayload_request_metadata_items_key', 'operationName_value', 'resourceId',
    'properties_requestbody', 'callerIpAddress', 'caller', 'properties_subscriptionId'
}

def load_config(config_path: str = 'config.yaml') -> Dict:
    if not os.path.exists(config_path):
        logging.warning(f"Config file {config_path} not found, using defaults")
        return {
            'input_dir': '.',
            'output_dir': './import',
            'log_level': 'INFO',
            'falcon_api': {
                'rulegroup_id': None,
                'enabled': True,
                'disposition_id': 2,
                'ruletype_id': '1',
                'pattern_severity': 'medium'
            },
            'platforms': ['windows', 'linux', 'mac', 'container'],
            'supported_fields': SUPPORTED_FIELDS,
            'regex_delimiters': ['/', '#'],
            'max_retries': 3,
            'retry_delay': 5
        }
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def infer_platforms(query: str, config: Dict) -> List[str]:
    query_lower = query.lower()
    platforms = []
    if 'win' in query_lower:
        platforms.append('windows')
    if 'lin' in query_lower or 'linux' in query_lower:
        platforms.append('linux')
    if 'mac' in query_lower:
        platforms.append('mac')
    if 'kubernetes' in query_lower or 'k8s' in query_lower or 'container' in query_lower:
        platforms.append('container')
    return platforms or config['platforms']

def map_severity(level: Optional[str], config: Dict) -> str:
    level_lower = level.lower() if level else ''
    if level_lower in ['critical', 'high']:
        return 'high'
    elif level_lower == 'medium':
        return 'medium'
    elif level_lower == 'low':
        return 'low'
    return config['falcon_api']['pattern_severity']

def validate_field(field: str, config: Dict) -> bool:
    if field not in config['supported_fields']:
        logging.warning(f"Unsupported field: {field}")
        return False
    return True

def parse_query_to_field_values(query: str, config: Dict) -> List[Dict]:
    field_values = []
    filter_part = query.split('|')[0].strip()
    # Replace IN with multiple assignments
    filter_part = re.sub(r'(\w+)\s+IN\s+\((.*?)\)', lambda m: ' '.join(f"{m.group(1)}={v.strip()}" for v in m.group(2).replace('"', '').split(',')), filter_part)
    filter_part = filter_part.replace(' LIKE ', '=').replace('~', '=')
    tokens = re.split(r'\s+', filter_part)
    i = 0
    current_field = None
    values = []
    op = None
    in_group = False
    while i < len(tokens):
        token = tokens[i].strip()
        if not token:
            i += 1
            continue
        if token.endswith('=') or token.endswith('~'):
            if current_field and values:
                if validate_field(current_field, config):
                    field_values.append(create_field_dict(current_field, op, values, config))
                current_field = None
                values = []
            current_field = token[:-1]
            op = token[-1]
            i += 1
            if i >= len(tokens):
                break
            value = tokens[i].strip()
            if value.startswith('('):
                in_group = True
                value = value[1:]
            if value.endswith(')'):
                in_group = False
                value = value[:-1]
            values.append(value)
        elif token == 'OR':
            i += 1
            if i >= len(tokens):
                break
            value = tokens[i].strip()
            values.append(value)
        elif token == '(':
            in_group = True
            i += 1
            continue
        elif token == ')':
            in_group = False
            if current_field and values:
                if validate_field(current_field, config):
                    field_values.append(create_field_dict(current_field, op, values, config))
                current_field = None
                values = []
            i += 1
            continue
        elif token.startswith('NOT'):
            logging.warning(f"Negation (NOT) in query: {token}. Not supported in FQL, noted in description.")
            i += 1
            continue
        else:
            if ':' in token or '=' in token:
                parts = re.split(r'([=~])', token)
                if len(parts) >= 2:
                    current_field = parts[0]
                    op = parts[1]
                    if len(parts) > 2:
                        values.append(parts[2].strip())
        i += 1

    if current_field and values:
        if validate_field(current_field, config):
            field_values.append(create_field_dict(current_field, op, values, config))

    return field_values

def create_field_dict(field: str, op: str, values: List[str], config: Dict) -> Dict:
    type_map = {
        '=': 'equals',
        '~': 'regex' if any(v.startswith(delim) for v in values for delim in config['regex_delimiters']) else 'contains'
    }
    value_type = type_map.get(op, 'equals')
    cleaned_values = []
    for v in values:
        for delim in config['regex_delimiters']:
            if v.startswith(delim) and v.endswith(delim):
                v = v[1:-1]
                break
        cleaned_values.append(v.strip('"'))
    return {
        "label": field,
        "type": "list" if len(cleaned_values) > 1 else "single",
        "values": [{"type": value_type, "value": v} for v in cleaned_values]
    }

def parse_md_file(file_path: str, config: Dict) -> List[Dict]:
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    rules = []
    current_name = None
    desc_lines = []
    in_desc = False
    in_sql = False
    sql_lines = []

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('### '):
            if sql_lines:
                rule = process_rule(current_name, '\n'.join(desc_lines).strip(), '\n'.join(sql_lines).strip(), config, file_path, line_num)
                if rule:
                    rules.append(rule)
                sql_lines = []
                desc_lines = []
            current_name = stripped[4:].strip()
            in_desc = True
            continue
        if in_desc and not stripped.startswith('---') and not stripped.startswith('```'):
            if stripped:
                desc_lines.append(stripped)
            continue
        if stripped == '```sql':
            in_sql = True
            in_desc = False
            sql_lines = []
            continue
        if in_sql:
            if stripped == '```':
                in_sql = False
                rule = process_rule(current_name, '\n'.join(desc_lines).strip(), '\n'.join(sql_lines).strip(), config, file_path, line_num)
                if rule:
                    rules.append(rule)
                sql_lines = []
                desc_lines = []
                current_name = None
            else:
                sql_lines.append(line.rstrip())
    if sql_lines:
        rule = process_rule(current_name, '\n'.join(desc_lines).strip(), '\n'.join(sql_lines).strip(), config, file_path, line_num)
        if rule:
            rules.append(rule)
    return rules

def process_rule(heading: Optional[str], description: str, query_raw: str, config: Dict, file_path: str, line_num: int) -> Optional[Dict]:
    if not query_raw.strip():
        logging.warning(f"No query content in {file_path} at line {line_num}")
        return None

    lines = query_raw.split('\n')
    comment_block = []
    query_lines = []
    in_comment = True

    for line in lines:
        stripped = line.strip()
        if in_comment and (stripped.startswith('--') or stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*') or 'comment' in stripped.lower()):
            comment_block.append(stripped)
        else:
            in_comment = False
            query_lines.append(line.rstrip())

    metadata = {'references': [], 'tags': [], 'falsepositives': []}
    current_key = None
    for comment in comment_block:
        comment = re.sub(r'^(--|#|//|/\*|\*/|\(comment, `|`)\s*', '', comment).strip()
        if ':' in comment:
            key, value = comment.split(':', 1)
            key = key.strip().lower().replace(' ', '_').replace('-', '_')
            value = value.strip()
            if key in ['references', 'tags', 'falsepositives']:
                metadata[key].append(value)
            else:
                metadata[key] = value
            current_key = key
        elif current_key and comment.startswith('- '):
            if current_key in ['references', 'tags', 'falsepositives']:
                metadata[current_key].append(comment[2:].strip())
        elif current_key:
            metadata[current_key] += ' ' + comment

    name = metadata.get('name') or metadata.get('title') or heading or 'Unnamed Rule'
    desc = metadata.get('description') or description
    if 'author' in metadata:
        desc += f"\nAuthor: {metadata['author']}"
    if 'date' in metadata:
        desc += f"\nDate: {metadata['date']}"
    if metadata['references']:
        desc += '\nReferences:\n' + '\n'.join(metadata['references'])
    if metadata['tags']:
        desc += '\nTags: ' + ', '.join(metadata['tags'])
    if metadata['falsepositives']:
        desc += '\nFalse Positives:\n' + '\n'.join(metadata['falsepositives'])
    level = metadata.get('level')

    query = '\n'.join(query_lines).strip()
    try:
        field_values = parse_query_to_field_values(query, config)
    except Exception as e:
        logging.error(f"Failed to parse query in {file_path} at line {line_num}: {e}")
        field_values = []

    platforms = infer_platforms(query, config)
    desc += f"\nInferred Platforms: {', '.join(platforms)}"

    rule_dict = {
        "name": name[:128],  # Falcon limit
        "description": desc[:4000],  # Falcon limit
        "field_values": field_values,
        "pattern_severity": map_severity(level, config),
        "enabled": config['falcon_api']['enabled'],
        "disposition_id": config['falcon_api']['disposition_id'],
        "ruletype_id": config['falcon_api']['ruletype_id'],
        "comment": f"Generated from {file_path} at line {line_num}"
    }
    if not field_values:
        rule_dict["description"] += f"\nWarning: Query parsing failed, original query: {query}"
    return rule_dict

def generate_jsons(config: Dict):
    os.makedirs(config['output_dir'], exist_ok=True)
    all_rules = []
    for root, _, files in os.walk(config['input_dir']):
        for file in files:
            if file.endswith('.md'):
                file_path = os.path.join(root, file)
                try:
                    rules = parse_md_file(file_path, config)
                    all_rules.extend(rules)
                except Exception as e:
                    logging.error(f"Error parsing {file_path}: {e}")
    for i, rule in enumerate(all_rules):
        name_slug = re.sub(r'[^a-zA-Z0-9_-]', '_', rule['name'].lower())[:50]
        json_path = os.path.join(config['output_dir'], f"{name_slug}_{i}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(rule, f, indent=4)
        logging.info(f"Generated: {json_path}")

def upload_to_falcon(config: Dict, rulegroup_id: Optional[str] = None):
    client_id = os.getenv('FALCON_CLIENT_ID')
    client_secret = os.getenv('FALCON_CLIENT_SECRET')
    if not client_id or not client_secret:
        raise ValueError("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET")

    falcon = CustomIOA(client_id=client_id, client_secret=client_secret)
    for file in os.listdir(config['output_dir']):
        if file.endswith('.json'):
            with open(os.path.join(config['output_dir'], file), 'r') as f:
                rule = json.load(f)
            body = {
                "name": rule["name"],
                "description": rule["description"],
                "field_values": rule["field_values"],
                "pattern_severity": rule["pattern_severity"],
                "enabled": rule["enabled"],
                "disposition_id": rule["disposition_id"],
                "ruletype_id": rule["ruletype_id"],
                "comment": rule["comment"]
            }
            if rulegroup_id or config['falcon_api']['rulegroup_id']:
                body["rulegroup_id"] = rulegroup_id or config['falcon_api']['rulegroup_id']
            for attempt in range(config['max_retries']):
                try:
                    response = falcon.create_rule(body=body)
                    if response["status_code"] == 201:
                        logging.info(f"Uploaded rule: {rule['name']}")
                        break
                    else:
                        logging.error(f"Attempt {attempt+1} failed for {rule['name']}: {response}")
                        if attempt < config['max_retries'] - 1:
                            time.sleep(config['retry_delay'])
                except Exception as e:
                    logging.error(f"Exception on attempt {attempt+1} for {rule['name']}: {e}")
                    if attempt < config['max_retries'] - 1:
                        time.sleep(config['retry_delay'])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CrowdStrike Falcon IOA Pipeline")
    parser.add_argument('--config', type=str, default='config.yaml', help="Path to config.yaml")
    parser.add_argument('--generate', action='store_true', help="Generate JSON files")
    parser.add_argument('--upload', action='store_true', help="Upload to Falcon")
    parser.add_argument('--rulegroup_id', type=str, help="Optional Rule Group ID")
    args = parser.parse_args()

    config = load_config(args.config)
    logging.getLogger().setLevel(config['log_level'])
    if args.generate:
        generate_jsons(config)
    if args.upload:
        upload_to_falcon(config, args.rulegroup_id)