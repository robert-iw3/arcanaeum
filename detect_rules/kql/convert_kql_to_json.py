import json
import re
import os
import argparse
import uuid

# Declare needed variables at the module level if necessary, but most are function-local.
# No global variables are needed beyond imports.

def parse_kql_file(file_path):
    """
    Parses a KQL file to extract metadata from comments and the query itself.
    Metadata is assumed to be in the format '// Key: Value' or '// Key: [List, of, values]'.
    Handles potential multi-line descriptions by appending unmatched comment lines to description.
    """
    metadata = {"displayName": None, "description": ""}
    tags = {}
    query_lines = []

    # Regex to capture "Key: Value" or "Key: [Value1, Value2]" from a comment.
    # The first group captures the key, the second captures the value(s).
    metadata_regex = re.compile(r'//\s*(?P<key>[A-Za-z\s]+):\s*(?P<value>.*)')

    in_metadata_section = True
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line_stripped = line.strip()

            # Stop parsing metadata once a non-comment line is encountered.
            if in_metadata_section and not line_stripped.startswith('//') and line_stripped:
                in_metadata_section = False

            if in_metadata_section and line_stripped.startswith('//'):
                match = metadata_regex.match(line_stripped)
                if match:
                    key = match.group('key').strip()
                    value = match.group('value').strip()

                    # Store special keys directly in the metadata dictionary.
                    if key.lower() == 'name':
                        metadata['displayName'] = value
                    elif key.lower() == 'description':
                        metadata['description'] = value
                    else:
                        # Split values by comma and store in a list for tags.
                        tags[key] = [v.strip() for v in value.split(',')]
                else:
                    # If comment but no key:value, append to description (potential multi-line desc).
                    desc_line = line_stripped[2:].strip()  # Remove '//'
                    if metadata['description']:
                        metadata['description'] += ' ' + desc_line
                    else:
                        metadata['description'] = desc_line
            else:
                query_lines.append(line)

    query = ''.join(query_lines).strip()
    return metadata, query, tags

def create_query_resource_json(metadata, query, tags, query_pack_name):
    """
    Constructs the JSON payload for a single Log Analytics Query Pack query resource.
    """
    display_name = metadata.get('displayName')
    if not display_name:
        # Fallback to a sanitized filename if no name is provided in comments.
        base_name = os.path.splitext(os.path.basename(metadata['source_file']))[0]
        display_name = re.sub(r'[^a-zA-Z0-9\s-]', '', base_name).replace('-', ' ').replace('_', ' ').title()

    # Ensure description exists
    if not metadata.get('description'):
        metadata['description'] = "No description provided."

    # Generate a unique GUID for the query.
    query_id = str(uuid.uuid4())

    # Build the query resource JSON
    query_resource = {
        "type": "queries",
        "apiVersion": "2025-02-01",
        "name": query_id,
        "dependsOn": [
            f"[resourceId('Microsoft.OperationalInsights/queryPacks', '{query_pack_name}')]"
        ],
        "properties": {
            "displayName": display_name,
            "description": metadata.get('description'),
            "body": query,
            "related": {
                "categories": ["Hunting Queries"],
                "resourceTypes": ["Microsoft.Security/securitySolutions"]
            },
            "tags": tags
        }
    }

    return query_resource

def create_arm_template(query_pack_name, location, query_resource):
    """
    Constructs the full ARM template.
    """
    arm_template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": [
            {
                "type": "Microsoft.OperationalInsights/queryPacks",
                "apiVersion": "2025-02-01",
                "name": query_pack_name,
                "location": location,
                "properties": {},
                "resources": [query_resource]
            }
        ]
    }
    return arm_template

def process_directory(input_dir, output_root_dir, query_pack_name, location):
    """
    Recursively walks through a directory, converts .kql files,
    and saves the output to a mirrored directory structure under 'import'.
    """
    print(f"Starting conversion for directory: {input_dir}\n")

    for root, _, files in os.walk(input_dir):
        for file_name in files:
            if file_name.endswith('.kql'):
                kql_file_path = os.path.join(root, file_name)

                try:
                    metadata, query, tags = parse_kql_file(kql_file_path)
                    metadata['source_file'] = kql_file_path

                    if not query:
                        print(f"Skipping {kql_file_path}: Could not extract query.")
                        continue

                    # Create the JSON for a single query resource
                    query_resource_json = create_query_resource_json(metadata, query, tags, query_pack_name)

                    # Wrap the query resource in a full ARM template
                    arm_template = create_arm_template(query_pack_name, location, query_resource_json)

                    relative_path = os.path.relpath(root, input_dir)
                    output_dir = os.path.join(output_root_dir, 'import', relative_path)

                    os.makedirs(output_dir, exist_ok=True)

                    output_filename_base = re.sub(r'[^a-zA-Z0-9\s-]', '', query_resource_json['properties']['displayName']).replace(' ', '-')
                    output_file_path = os.path.join(output_dir, f"{output_filename_base}.json")

                    with open(output_file_path, 'w', encoding='utf-8') as f:
                        json.dump(arm_template, f, indent=2)

                    print(f"Converted '{metadata.get('displayName') or output_filename_base}' from {kql_file_path}")

                except Exception as e:
                    print(f"An error occurred processing {kql_file_path}: {e}")

def main():
    """
    Main function to run the recursive conversion script.
    """
    parser = argparse.ArgumentParser(description="Recursively convert all .kql files in a directory to Log Analytics Query Pack JSON files.")
    parser.add_argument('input_directory', nargs='?', default='.', help="Path to the root directory containing .kql files. Defaults to current working directory.")
    parser.add_argument('--output-root', dest='output_root', default='.', help="Root directory for the output 'import' folder.")
    parser.add_argument('--query-pack-name', required=True, help="The name of the Log Analytics Query Pack.")
    parser.add_argument('--location', required=True, help="The Azure region for the Query Pack (e.g., eastus).")

    args = parser.parse_args()

    if not os.path.isdir(args.input_directory):
        print(f"Error: The input directory '{args.input_directory}' does not exist.")
        return

    process_directory(args.input_directory, args.output_root, args.query_pack_name, args.location)
    print("\nConversion complete.")

if __name__ == "__main__":
    main()