#!/usr/bin/env python3
"""
parse_md_to_json.py - Robust conversion of threat intel Markdown → SentinelOne DV JSON
Handles messy markdown, multiple comment styles, various code block formats
"""

import os
import json
import re
import argparse
import yaml
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

def load_config(config_path: str = "pipeline-config.yaml") -> Dict:
    config_path = Path(config_path)
    if not config_path.is_file():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    defaults = {
        "sentinelone": {"sites": ["<SITE_ID_1>"], "api_url": ""},
        "parsing": {"markdown_files": []},
        "output": {
            "json_directory": "./generated_queries",
            "time_range": {"from": "2025-01-01T00:00:00.000Z", "to": "2026-01-11T23:59:59.999Z"},
            "limit": 1000,
            "query_type": "events",
            "is_live": True
        }
    }

    # Merge defaults recursively
    def deep_merge(target, source):
        for k, v in source.items():
            if isinstance(v, dict) and k in target and isinstance(target[k], dict):
                deep_merge(target[k], v)
            else:
                target[k] = v

    deep_merge(defaults, config)
    return defaults

def extract_query_text(content: str) -> Optional[str]:
    """Try multiple strategies to find SQL/KQL/query content"""
    patterns = [
        r'```(?:sql|kql|query|dql)?\s*(.+?)\s*```',           # Standard with optional language
        r'```(?:\w+)?\s*\n(.+?)\n\s*```',                      # Language on separate line
        r'(?:(?:^|\n)(?: {4}|\t).+?(?=\n\n|$))',               # Indented code block
    ]

    for pattern in patterns:
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip()

    return None


def extract_comment_block(full_block: str) -> tuple[str, str]:
    """Extract comment and clean query - very tolerant version"""
    comment_patterns = [
        (r'/\*(.+?)\*/', True),                    # multi-line /* */
        (r'(?://\s*.+?(?:\n|$))+', False),         # // lines
        (r'(?:#.*(?:\n|$))+', False),              # # lines
        (r'(?:--.*(?:\n|$))+', False),             # -- lines
        (r'/\*(?:.|\n)*?\*/', True),               # greedy multi-line
    ]

    for pattern, is_multi in comment_patterns:
        matches = list(re.finditer(pattern, full_block, re.DOTALL | re.MULTILINE))
        if matches:
            comment_parts = []
            last_end = 0
            for m in matches:
                comment_parts.append(m.group(1 if is_multi else 0).strip())
                # Remove comment from query
                full_block = full_block[:m.start()] + full_block[m.end():]
            comment_text = "\n".join(comment_parts).strip()
            return comment_text, full_block.strip()

    return "", full_block.strip()


def extract_metadata(comment_text: str) -> Dict[str, str]:
    result = {"name": "", "description": ""}

    # More flexible title detection
    for pattern in [
        r'(?:Title|Detection Name|Name|Rule Name|Hunt Name):\s*(.+?)(?:\n|$)',
        r'^[#*]+\s*(.+?)(?:\n|$)',  # markdown header as fallback
        r'([A-Za-z0-9 _\-#&|]+?)(?:\n\s*-|\n\s*=|\n{2,})',  # first line that looks like title
    ]:
        m = re.search(pattern, comment_text, re.I | re.MULTILINE)
        if m:
            result["name"] = m.group(1).strip()
            break

    # Description - take first substantial paragraph after title
    desc_match = re.search(
        r'(?:Description|Summary|About):\s*(.+?)(?=\n\s*[A-Z][a-z]|\n{3,}|$)',
        comment_text, re.I | re.DOTALL
    )
    if desc_match:
        result["description"] = desc_match.group(1).strip()

    return result


def parse_md_file(file_path: Path) -> List[Dict[str, str]]:
    queries = []
    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception as e:
        print(f"× Failed to read {file_path}: {e}")
        return queries

    # Split on level 3 headings (###)
    sections = re.split(r'^###\s*(.+?)$', content, flags=re.MULTILINE)
    if len(sections) < 3:
        print(f"⚠ No ### sections found in {file_path}")
        return queries

    for i in range(1, len(sections), 2):
        header = sections[i].strip()
        section_content = sections[i + 1].strip()

        query_text = extract_query_text(section_content)
        if not query_text or len(query_text) < 30:  # arbitrary minimal length
            continue

        comment, clean_query = extract_comment_block(query_text)
        metadata = extract_metadata(comment)

        name = metadata["name"] or header or f"unnamed_query_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        queries.append({
            "name": name,
            "query": clean_query,
            "description": metadata["description"],
            "source_header": header,
            "source_file": str(file_path)
        })

    return queries


def safe_filename(name: str) -> str:
    """Very aggressive sanitization + collision protection"""
    name = re.sub(r'[^a-zA-Z0-9_-]', '_', name.lower().strip())
    name = re.sub(r'_+', '_', name)
    name = name.strip('_')
    return name or "unnamed"


def generate_json_files(queries: List[Dict], config: Dict):
    output_dir = Path(config["output"]["json_directory"])
    output_dir.mkdir(parents=True, exist_ok=True)

    scope = config["sentinelone"]["sites"]
    from_time = config["output"]["time_range"]["from"]
    to_time = config["output"]["time_range"]["to"]
    limit = config["output"]["limit"]

    generated = []
    seen_names = set()

    for q in queries:
        base_name = safe_filename(q["name"])
        name = base_name
        counter = 1
        while name in seen_names:
            name = f"{base_name}_{counter}"
            counter += 1
        seen_names.add(name)

        json_path = output_dir / f"{name}.json"

        data = {
            "queryText": q["query"],
            "queryType": config["output"]["query_type"],
            "isLive": config["output"]["is_live"],
            "scope": scope,
            "limit": limit,
            "fromTime": from_time,
            "toTime": to_time,
            # Optional useful metadata for humans
            "_metadata": {
                "name": q["name"],
                "description": q["description"],
                "source": f"{q['source_file']} → {q['source_header']}"
            }
        }

        try:
            json_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
            generated.append(str(json_path))
            print(f"✓ {json_path}")
        except Exception as e:
            print(f"✗ Failed to write {json_path}: {e}")

    return generated


def main():
    parser = argparse.ArgumentParser(description="Robust Markdown → SentinelOne DV JSON converter")
    parser.add_argument("--config", default="pipeline-config.yaml", help="Config YAML path")
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Configuration error: {e}")
        return

    md_files = config["parsing"].get("markdown_files", [])
    if not md_files:
        print("No markdown_files defined in config.")
        return

    all_generated = []
    for rel_path in md_files:
        path = Path(rel_path)
        if not path.is_file():
            print(f"File not found: {path}")
            continue

        print(f"\nProcessing: {path}")
        queries = parse_md_file(path)

        if queries:
            print(f"  Found {len(queries)} queries")
            generated = generate_json_files(queries, config)
            all_generated.extend(generated)
        else:
            print("  No usable queries found")

    if all_generated:
        print(f"\nSuccess! Created {len(all_generated)} JSON files in:")
        print(f"  {config['output']['json_directory']}")
    else:
        print("\nNothing was generated. Check markdown format and config.")


if __name__ == "__main__":
    main()