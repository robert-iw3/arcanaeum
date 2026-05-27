import unittest
import yaml
import re
import json
import os
import time
from pathlib import Path
from jsonschema import validate, ValidationError
from collections import Counter
import coverage

# Datadog JSON schema for signal correlation rules
DATADOG_RULE_SCHEMA = {
    "type": "object",
    "required": ["data"],
    "properties": {
        "data": {
            "type": "object",
            "required": ["type", "attributes"],
            "properties": {
                "type": {"type": "string", "enum": ["signal_correlation"]},
                "attributes": {
                    "type": "object",
                    "required": ["name", "enabled", "cases", "group_by_fields", "distinct_fields", "correlation", "message", "severity", "tags", "options"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "enabled": {"type": "boolean"},
                        "cases": {
                            "type": "array",
                            "minItems": 1,
                            "items": {
                                "type": "object",
                                "required": ["name", "status", "query"],
                                "properties": {
                                    "name": {"type": "string", "minLength": 1},
                                    "status": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                                    "query": {"type": "string", "minLength": 1}
                                }
                            }
                        },
                        "group_by_fields": {"type": "array", "items": {"type": "string"}},
                        "distinct_fields": {"type": "array", "items": {"type": "string"}},
                        "correlation": {
                            "type": "object",
                            "required": ["expression", "timeframe"],
                            "properties": {
                                "expression": {"type": "string", "minLength": 1},
                                "timeframe": {"type": "string", "pattern": "^\\d+[smhd]$"}
                            }
                        },
                        "message": {"type": "string"},
                        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "options": {
                            "type": "object",
                            "required": ["evaluation_window"],
                            "properties": {
                                "evaluation_window": {"type": "string", "pattern": "^\\d+[smhd]$"}
                            }
                        },
                        "rule_id": {"type": "string", "minLength": 1}
                    }
                }
            }
        }
    }
}

class TestMetricsLogger:
    """Track and save test metrics for DevOps pipeline."""
    def __init__(self):
        self.metrics = {
            "total_files": 0,
            "files_passed": 0,
            "files_failed": 0,
            "total_rules": 0,
            "rules_passed": 0,
            "rules_failed": 0,
            "case_counts": {},
            "failure_reasons": [],
            "test_duration_seconds": 0,
            "coverage_percentage": 0.0
        }
        self.start_time = time.time()
        self.cov = coverage.Coverage(source=["."], omit=["*/test_*.py"])
        self.cov.start()

    def log_file(self, file_path, passed, failure_reason=None):
        self.metrics["total_files"] += 1
        if passed:
            self.metrics["files_passed"] += 1
        else:
            self.metrics["files_failed"] += 1
            if failure_reason:
                self.metrics["failure_reasons"].append({"file": str(file_path), "reason": failure_reason})

    def log_rule(self, file_path, passed, case_count, failure_reason=None):
        self.metrics["total_rules"] += 1
        self.metrics["case_counts"][str(file_path)] = self.metrics["case_counts"].get(str(file_path), 0) + case_count
        if passed:
            self.metrics["rules_passed"] += 1
        else:
            self.metrics["rules_failed"] += 1
            if failure_reason:
                self.metrics["failure_reasons"].append({"file": str(file_path), "reason": failure_reason})

    def save_metrics(self, output_path="test_metrics.json"):
        self.cov.stop()
        self.cov.save()
        self.metrics["test_duration_seconds"] = time.time() - self.start_time
        self.metrics["coverage_percentage"] = self.cov.json_report(outfile="coverage.json")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.metrics, f, indent=2)

class TestDatadogRuleConversion(unittest.TestCase):
    def setUp(self):
        self.output_dir = Path("signal_correlation_rules")
        self.output_dir.mkdir(exist_ok=True)
        self.rules_dir = Path("rules")
        self.rules_dir.mkdir(exist_ok=True)
        self.metrics_logger = TestMetricsLogger()
        # Mock sample files for controlled testing
        self.sample_files = {
            "rules/hashicorp_vault_0day_detections.md": """
            ### HashiCorp Vault Zero-Day Vulnerabilities Report
            ```sql
            source:vault error:* request.path:/auth/userpass/login/* | extract_username(request.path:/auth/userpass/login/{username}) | timeslice(10m) | groupby(src_ip, timeslice) | agg(distinct_user_count:distinct(username), attempted_users:collect(username), failed_logins:count(), avg_duration_ms:avg(response.duration_ms), stdev_duration_ms:stdev(response.duration_ms)) | filter(distinct_user_count > 15 AND failed_logins > 20) | select(-timeslice)
            ```
            ```sql
            source:vault (request.path:/mfa/validate OR auth.method_type:totp) | extract_passcode(request.body:passcode[\\'\\"]\\s*:\\s*[\\'\\"]{passcode}) | eval(numeric_passcode:replace(passcode, "\\s", "")) | filter(numeric_passcode IS NOT NULL AND length(numeric_passcode) > 0) | timeslice(5m) | groupby(src_ip, entity_id, numeric_passcode, timeslice) | agg(distinct_passcode_variations:distinct(passcode), attempted_passcodes:collect(passcode), attempt_count:count()) | filter(distinct_passcode_variations > 1) | select(-timeslice)
            ```
            ```sql
            source:vault request.path:/auth/cert/login auth.token_type:service | filter(auth.metadata.cert_name IS NOT NULL AND auth.alias_name IS NOT NULL AND auth.metadata.cert_name != auth.alias_name) | select(time, src_ip:request.remote_address, cert_role_name:auth.metadata.cert_name, impersonated_cn_alias:auth.alias_name, entity_id:auth.entity_id)
            ```
            ```sql
            source:vault request.path:/identity/entity/id/* request.method:POST | mvexpand(assigned_policy:request.data.policies) | eval(normalized_policy:lower(trim(assigned_policy))) | filter(normalized_policy == "root" AND assigned_policy != "root") | select(time, src_ip:request.remote_address, user:auth.display_name, target_entity_path:request.path, assigned_policy)
            ```
            ```sql
            source:vault request.path:/sys/audit/* (request.method:PUT OR request.method:POST) request.data.type:file request.data.options.mode:* | eval(mode:request.data.options.mode, mode_len:length(mode), owner_perm:substring(mode, mode_len-2, 1), group_perm:substring(mode, mode_len-1, 1), other_perm:substring(mode, mode_len, 1)) | filter(owner_perm IN ("1","3","5","7") OR group_perm IN ("1","3","5","7") OR other_perm IN ("1","3","5","7")) | select(time, src_ip:request.remote_address, user:auth.display_name, target_audit_device:request.path, audit_file_path:request.data.options.file_path, file_mode:request.data.options.mode)
            ```
            """,
            "rules/linux_persistence_common_TTPs.md": """
            ### Linux Persistence Strategies
            ```sql
            source:linux (@process.name:crontab OR ((@process.cmdline:"* > *" OR @process.cmdline:"* >> *") AND (@process.cmdline:"*/etc/cron*" OR @process.cmdline:"*/var/spool/cron*"))) (@process.cmdline:"*/dev/tcp/*" OR @process.cmdline:"*/dev/udp/*" OR @process.cmdline:"*nc *" OR @process.cmdline:"*netcat *" OR @process.cmdline:"*bash -i*")
            ```
            ```sql
            source:linux @network.direction:outbound @network.destination.port:(4444 OR 8080 OR 53 OR 80 OR 443) (@process.name:(bash OR sh OR zsh OR ksh OR csh OR perl OR php OR ruby OR pwsh OR nc OR netcat OR ncat) OR @process.name:python*)
            ```
            """,
            "rules/critical_infra_attacks_irgc.md": """
            ### Intrusion into Middle East Critical National Infrastructure
            ```sql
            source:email status:delivered recipient.is_admin:true NOT sender_domain:internal_domains (subject:/(password|verify|urgent|action required|suspension|invoice|credentials|security alert|account validation)/ OR file.name:/\\.(html|htm|zip|iso|lnk,vbs,js)$/) | select sender AS email_sender, recipient AS email_recipient, subject AS email_subject, file.name AS attachment_name, ip.src AS source_ip, min(timestamp) AS firstTime, max(timestamp) AS lastTime | aggregate count by email_sender, email_recipient, email_subject, attachment_name, source_ip | select strftime(firstTime, "%Y-%m-%d %H:%M:%S") AS firstTime, strftime(lastTime, "%Y-%m-%d %H:%M:%S") AS lastTime, email_sender, email_recipient, email_subject, attachment_name, source_ip
            ```
            """,
            "rules/misc-detection-rules.md": """
            ## Miscellaneous Custom Detection Rules for Datadog
            ```yaml
            name: SQLi Detection
            type: signal_correlation
            cases:
              - name: SQLi Authentication Bypass
                status: high
                query: '@event.outcome:(0 OR success OR allow OR accepted) AND @user.name:(*\\'\\ or\\ * OR *\\'or\\'--* OR *\\ or\\ 1=1* OR *admin\\'--*)'
              - name: Time-Based Blind SQLi
                status: medium
                query: '@http.status_code:(200 OR 301 OR 302 OR 400 OR 401 OR 403 OR 500) AND @http.url:(*sleep* OR *waitfor* OR *benchmark* OR *pg_sleep*)'
            signal_correlation:
              rule_id: sqli_detection
              group_by_fields:
                - '@host'
                - '@user.name'
                - '@destination.ip'
              distinct_fields:
                - case_id
              correlation:
                expression: distinct_count >= 1
                timeframe: 1h
            message: 'SQLi Attempt: {distinct_count} type(s) from source {@client.ip} by user {@user.name} to destination {@destination.ip}: {case_names}'
            severity: high
            tags:
              - security:attack
            options:
              evaluation_window: 1h
            ```
            ```yaml
            name: SQLi Detection
            type: signal_correlation
            cases:
              - name: SQLi Authentication Bypass Duplicate
                status: high
                query: '@event.outcome:(0 OR success OR allow OR accepted) AND @user.name:(*\\'\\ or\\ * OR *\\'or\\'--* OR *\\ or\\ 1=1* OR *admin\\'--*)'
            signal_correlation:
              rule_id: sqli_detection_duplicate
              group_by_fields:
                - '@host'
              distinct_fields:
                - case_id
              correlation:
                expression: distinct_count >= 1
                timeframe: 1h
            message: 'Duplicate SQLi Attempt: {distinct_count} type(s) from source {@client.ip}'
            severity: high
            tags:
              - security:attack
            options:
              evaluation_window: 1h
            ```
            """,
            "rules/subdir/empty_file.md": "",
            "rules/subdir/invalid_yaml.md": """
            ```yaml
            name: Invalid Rule
            type: signal_correlation
            cases:
              - name: Invalid Case
                status: invalid_status
                query: ''
            ```
            """,
            "rules/subdir/invalid_query.md": """
            ```sql
            invalid query without source
            ```
            ```sql
            source:linux (unclosed parenthesis
            ```
            """
        }
        # Create mock files
        for file_path, content in self.sample_files.items():
            file_path = Path(file_path)
            file_path.parent.mkdir(exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)

    def tearDown(self):
        # Clean up mock files and output directory
        for file_path in self.sample_files:
            if Path(file_path).exists():
                os.remove(file_path)
        for json_file in self.output_dir.glob('*.json'):
            os.remove(json_file)
        if self.output_dir.exists():
            self.output_dir.rmdir()
        for subdir in self.rules_dir.glob('subdir'):
            if subdir.is_dir():
                subdir.rmdir()
        if self.rules_dir.exists():
            self.rules_dir.rmdir()
        self.metrics_logger.save_metrics()

    def parse_markdown_yaml(self, content, file_path):
        """Parse Markdown or YAML content, handling multiple YAML and SQL blocks."""
        if file_path.suffix in ['.yaml', '.yml']:
            try:
                rule_data = yaml.safe_load(content)
                if not rule_data or 'name' not in rule_data or 'type' not in rule_data:
                    return []
                return [rule_data]
            except yaml.YAMLError:
                return []
        else:
            yaml_pattern = r'```yaml\n([\s\S]*?)\n```'
            sql_pattern = r'```sql\n([\s\S]*?)\n```'
            yaml_matches = re.findall(yaml_pattern, content)
            sql_matches = re.findall(sql_pattern, content)

            if not yaml_matches and not sql_matches:
                return []

            rule_data_list = []
            if yaml_matches:
                for yaml_content in yaml_matches:
                    try:
                        rule_data = yaml.safe_load(yaml_content)
                        if not rule_data or 'name' not in rule_data or 'type' not in rule_data:
                            continue
                        rule_data_list.append(rule_data)
                    except yaml.YAMLError:
                        continue
            else:
                rule_data = {
                    "name": Path(file_path).stem.replace('_', ' ').title(),
                    "type": "signal_correlation",
                    "signal_correlation": {
                        "group_by_fields": [],
                        "distinct_fields": ["case_id"],
                        "correlation": {"expression": "distinct_count >= 1", "timeframe": "1h"}
                    },
                    "message": f"Generated from {file_path}",
                    "severity": "medium",
                    "tags": [],
                    "options": {"evaluation_window": "1h"},
                    "cases": []
                }
                rule_data_list.append(rule_data)

            for rule_data in rule_data_list:
                if sql_matches:
                    rule_data["cases"] = rule_data.get("cases", [])
                    for j, sql_query in enumerate(sql_matches, 1):
                        sql_query = sql_query.strip()
                        if not sql_query:
                            continue
                        case = {
                            "name": f"Case {j}",
                            "status": rule_data.get("severity", "medium"),
                            "query": sql_query
                        }
                        rule_data["cases"].append(case)
                    sql_matches = []
                if not rule_data.get("cases"):
                    rule_data_list.remove(rule_data)

            return rule_data_list

    def mock_datadog_query_executor(self, query, file_path, case_name):
        """Mock Datadog query executor for deeper validation."""
        known_sources = {'vault', 'linux', 'email', 'cloudtrail'}
        operators = {'AND', 'OR', 'NOT'}
        aggregations = {'groupby', 'agg', 'filter', 'select', 'eval', 'mvexpand', 'timeslice'}

        # Tokenize query (simplified, not a full parser)
        tokens = re.split(r'\s+|\(|\)|,|:', query)
        tokens = [t for t in tokens if t]

        # Check source
        if not tokens[0].startswith('source:'):
            return False, f"Query missing 'source:' prefix in case {case_name} for {file_path}"
        source = tokens[0].replace('source:', '')
        if source not in known_sources:
            return False, f"Unknown source '{source}' in case {case_name} for {file_path}"

        # Check field references and operators
        for token in tokens:
            if token.startswith('@') and not re.match(r'@[a-zA-Z0-9._-]+$', token):
                return False, f"Invalid field reference '{token}' in case {case_name} for {file_path}"
            if token in operators:
                continue
            if token in aggregations:
                continue
            if token.startswith('(') or token.endswith(')') or token in {',', ':'}:
                continue
            if not re.match(r'[a-zA-Z0-9._*=/]+$', token):
                return False, f"Invalid token '{token}' in case {case_name} for {file_path}"

        # Check balanced parentheses
        paren_count = 0
        for char in query:
            if char == '(':
                paren_count += 1
            elif char == ')':
                paren_count -= 1
            if paren_count < 0:
                return False, f"Unbalanced parentheses in case {case_name} for {file_path}"
        if paren_count != 0:
            return False, f"Unbalanced parentheses in case {case_name} for {file_path}"

        # Check balanced quotes
        quote_count = Counter(query)
        if quote_count.get('"', 0) % 2 != 0 or quote_count.get("'", 0) % 2 != 0:
            return False, f"Unbalanced quotes in case {case_name} for {file_path}"

        # Check non-empty clauses
        for agg in ['filter', 'groupby', 'agg']:
            if f"{agg}(" in query:
                match = re.search(rf"{agg}\((.*?)\)", query)
                if match and not match.group(1).strip():
                    return False, f"Empty {agg} clause in case {case_name} for {file_path}"

        return True, None

    def validate_query_syntax(self, query, file_path, case_name):
        """Validate Datadog SQL query syntax."""
        if not query.startswith("source:"):
            return False, f"Query missing 'source:' prefix in case {case_name} for {file_path}"

        source_match = re.match(r"source:([a-zA-Z0-9_-]+)", query)
        if not source_match:
            return False, f"Invalid source in case {case_name} for {file_path}"

        datadog_syntax = re.search(r"(@[a-zA-Z0-9._-]+|\||groupby\(|agg\(|filter\()", query)
        if not datadog_syntax and not re.search(r"\b(source:[a-zA-Z0-9_-]+)\b", query):
            return False, f"Missing Datadog syntax (@field, |, groupby, agg, filter) in case {case_name} for {file_path}"

        return self.mock_datadog_query_executor(query, file_path, case_name)

    def validate_json(self, json_data, file_path):
        """Validate JSON against Datadog schema and best practices."""
        try:
            validate(instance=json_data, schema=DATADOG_RULE_SCHEMA)
            attributes = json_data["data"]["attributes"]
            if len(attributes["cases"]) == 0:
                self.metrics_logger.log_rule(file_path, False, 0, "No cases defined")
                self.fail(f"No cases defined in {file_path}")
            for case in attributes["cases"]:
                if not case["query"]:
                    self.metrics_logger.log_rule(file_path, False, 0, f"Empty query in case {case['name']}")
                    self.fail(f"Empty query in case {case['name']} for {file_path}")
                if case["status"] not in ["low", "medium", "high", "critical"]:
                    self.metrics_logger.log_rule(file_path, False, 0, f"Invalid status in case {case['name']}")
                    self.fail(f"Invalid status in case {case['name']} for {file_path}")
                valid, reason = self.validate_query_syntax(case["query"], file_path, case["name"])
                if not valid:
                    self.metrics_logger.log_rule(file_path, False, 0, reason)
                    self.fail(reason)
            if not attributes["name"]:
                self.metrics_logger.log_rule(file_path, False, 0, "Empty rule name")
                self.fail(f"Empty rule name in {file_path}")
            if not attributes["correlation"]["expression"]:
                self.metrics_logger.log_rule(file_path, False, 0, "Empty correlation expression")
                self.fail(f"Empty correlation expression in {file_path}")
            if not re.match(r"^\d+[smhd]$", attributes["correlation"]["timeframe"]):
                self.metrics_logger.log_rule(file_path, False, 0, "Invalid timeframe")
                self.fail(f"Invalid timeframe in {file_path}")
            return True
        except ValidationError as e:
            self.metrics_logger.log_rule(file_path, False, 0, f"Schema validation failed: {str(e)}")
            self.fail(f"JSON validation failed for {file_path}: {str(e)}")
            return False

    def convert_to_datadog_json(self, rule_data, file_path):
        """Convert parsed rule data to Datadog JSON format."""
        if not rule_data:
            return None

        json_template = {
            "data": {
                "type": "signal_correlation",
                "attributes": {
                    "name": rule_data.get('name', 'Unnamed Rule'),
                    "enabled": rule_data.get('is_enabled', True),
                    "cases": [],
                    "group_by_fields": rule_data.get('signal_correlation', {}).get('group_by_fields', []),
                    "distinct_fields": rule_data.get('signal_correlation', {}).get('distinct_fields', ["case_id"]),
                    "correlation": {
                        "expression": rule_data.get('signal_correlation', {}).get('correlation', {}).get('expression', "distinct_count >= 1"),
                        "timeframe": rule_data.get('signal_correlation', {}).get('correlation', {}).get('timeframe', "1h")
                    },
                    "message": rule_data.get('message', ''),
                    "severity": rule_data.get('severity', 'high'),
                    "tags": rule_data.get('tags', []),
                    "options": rule_data.get('options', {"evaluation_window": "1h"})
                }
            }
        }

        for case in rule_data.get('cases', []):
            json_case = {
                "name": case.get('name', ''),
                "status": case.get('status', 'medium'),
                "query": case.get('query', '')
            }
            json_template['data']['attributes']['cases'].append(json_case)

        if rule_data.get('signal_correlation', {}).get('rule_id'):
            json_template['data']['attributes']['rule_id'] = rule_data['signal_correlation']['rule_id']

        return json_template

    def save_json(self, json_data, file_path, rule_name, rule_names):
        """Save JSON to file with name-based filename, handling duplicates."""
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', rule_name.lower())
        base_name = safe_name
        suffix = 1
        while safe_name in rule_names:
            safe_name = f"{base_name}_{suffix}"
            suffix += 1
        rule_names.add(safe_name)
        output_file = self.output_dir / f"{safe_name}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2)
        return output_file

    def test_all_rules_conversion(self):
        """Test conversion of all files in rules/ directory and subdirectories."""
        rule_names = set()
        files = list(self.rules_dir.rglob('*.[mM][dD]')) + list(self.rules_dir.rglob('*.[yY][aA][mM][lL]'))
        self.assertGreater(len(files), 0, "No Markdown or YAML files found in rules/ directory")

        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                rule_data_list = self.parse_markdown_yaml(content, file_path)
                if not rule_data_list:
                    self.metrics_logger.log_file(file_path, file_path.name in ["empty_file.md", "invalid_yaml.md", "invalid_query.md"],
                                                "No valid rules parsed" if file_path.name not in ["empty_file.md", "invalid_yaml.md", "invalid_query.md"] else None)
                    self.assertIn(file_path.name, ["empty_file.md", "invalid_yaml.md", "invalid_query.md"],
                                  f"Expected no rules for {file_path} unless empty or invalid")
                    continue

                for rule_data in rule_data_list:
                    self.assertTrue(rule_data.get("name"), f"Rule name missing in {file_path}")
                    self.assertEqual(rule_data.get("type"), "signal_correlation", f"Invalid rule type in {file_path}")
                    case_count = len(rule_data.get("cases", []))
                    self.assertGreater(case_count, 0, f"No cases defined in {file_path}")

                    json_data = self.convert_to_datadog_json(rule_data, file_path)
                    self.assertTrue(self.validate_json(json_data, file_path), f"JSON validation failed for {file_path}")

                    output_file = self.save_json(json_data, file_path, rule_data["name"], rule_names)
                    self.assertTrue(output_file.exists(), f"Failed to save JSON for {file_path}")
                    with open(output_file, 'r', encoding='utf-8') as f:
                        saved_json = json.load(f)
                    self.assertEqual(saved_json, json_data, f"Saved JSON does not match for {file_path}")
                    self.metrics_logger.log_rule(file_path, True, case_count)

                self.metrics_logger.log_file(file_path, True)
            except Exception as e:
                self.metrics_logger.log_file(file_path, False, str(e))
                self.fail(f"Failed to process {file_path}: {str(e)}")

if __name__ == "__main__":
    unittest.main()