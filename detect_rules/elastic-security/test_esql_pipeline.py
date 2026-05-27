import unittest
import tempfile
from pathlib import Path
from esql_pipeline import validate_esql_query, fix_esql_query, extract_esql_from_markdown, validate_ndjson, load_config, import_to_kibana
import responses

class TestESQLPipeline(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.maxDiff = None

    def test_validate_esql_query_valid(self):
        query = "from winlogbeat-* | where winlog.event_id = '5136' and host.name = 'test' | keep host.name"
        self.assertTrue(validate_esql_query(query))

    def test_validate_esql_query_invalid(self):
        query = "select * from logs where hostname = 'test'"
        self.assertFalse(validate_esql_query(query))

    def test_fix_esql_query(self):
        query = "from logs-* | where hostname = 'test' and src_ip = '192.168.1.1' and username = 'admin'"
        result = fix_esql_query(query)
        expected_query = "from logs-* | where host.name = 'test' and source.ip = '192.168.1.1' and user.name = 'admin'"
        self.assertEqual(result['query'], expected_query)
        self.assertEqual(result['original_query'], query)

    def test_fix_esql_query_custom_fields(self):
        query = "from logs-* | where custom_field = 'value' and src_addr = '10.0.0.1'"
        result = fix_esql_query(query)
        expected_query = "from logs-* | where labels.custom_field = 'value' and source.ip = '10.0.0.1'"
        self.assertEqual(result['query'], expected_query)
        self.assertEqual(result['original_query'], query)

    @responses.activate
    def test_extract_esql_from_markdown_enterprise(self):
        responses.add(
            responses.GET,
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
            json={
                "objects": [
                    {
                        "type": "x-mitre-tactic",
                        "x_mitre_shortname": "TA0001",
                        "name": "Initial Access",
                        "external_references": [{"external_id": "TA0001", "url": "https://attack.mitre.org/tactics/TA0001/"}]
                    },
                    {
                        "type": "attack-pattern",
                        "external_references": [{"external_id": "T1190", "url": "https://attack.mitre.org/techniques/T1190/"}],
                        "name": "Exploit Public-Facing Application"
                    }
                ]
            },
            status=200
        )

        markdown_content = """
---
name: Test Rule
description: Test description
severity: high
tags: [Test, ESQL]
matrix: enterprise
tactics:
  - id: TA0001
    techniques:
      - id: T1190
---
# Test Rule
```sql
from winlogbeat-* | where hostname = 'test' and event_id = '5136'
```
"""
        md_file = self.temp_dir / "test.md"
        md_file.write_text(markdown_content, encoding='utf-8')

        rules = extract_esql_from_markdown(md_file)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["query"], "from winlogbeat-* | where host.name = 'test' and winlog.event_id = '5136'")
        self.assertEqual(rules[0]["meta"]["original_query"], "from winlogbeat-* | where hostname = 'test' and event_id = '5136'")
        self.assertEqual(rules[0]["name"], "Test Rule")
        self.assertEqual(rules[0]["ecs_version"], "9.1.0")
        self.assertEqual(rules[0]["threat"][0]["tactic"]["id"], "TA0001")
        self.assertEqual(rules[0]["threat"][0]["technique"][0]["id"], "T1190")

    @responses.activate
    def test_extract_esql_from_markdown_mobile(self):
        responses.add(
            responses.GET,
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
            json={
                "objects": [
                    {
                        "type": "x-mitre-tactic",
                        "x_mitre_shortname": "TA0027",
                        "name": "Application Access Token",
                        "external_references": [{"external_id": "TA0027", "url": "https://attack.mitre.org/tactics/TA0027/"}]
                    },
                    {
                        "type": "attack-pattern",
                        "external_references": [{"external_id": "T1635", "url": "https://attack.mitre.org/techniques/T1635/"}],
                        "name": "Steal Application Access Token"
                    }
                ]
            },
            status=200
        )

        markdown_content = """
---
name: Mobile Rule
matrix: mobile
tactics:
  - id: TA0027
    techniques:
      - id: T1635
---
```sql
from logs-* | where client_ip = '192.168.1.1'
```
"""
        md_file = self.temp_dir / "mobile.md"
        md_file.write_text(markdown_content, encoding='utf-8')

        rules = extract_esql_from_markdown(md_file)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["query"], "from logs-* | where source.ip = '192.168.1.1'")
        self.assertEqual(rules[0]["meta"]["original_query"], "from logs-* | where client_ip = '192.168.1.1'")
        self.assertEqual(rules[0]["threat"][0]["tactic"]["id"], "TA0027")

    @responses.activate
    def test_extract_esql_from_markdown_ics(self):
        responses.add(
            responses.GET,
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
            json={
                "objects": [
                    {
                        "type": "x-mitre-tactic",
                        "x_mitre_shortname": "TA0104",
                        "name": "Execution",
                        "external_references": [{"external_id": "TA0104", "url": "https://attack.mitre.org/tactics/TA0104/"}]
                    },
                    {
                        "type": "attack-pattern",
                        "external_references": [{"external_id": "T0865", "url": "https://attack.mitre.org/techniques/T0865/"}],
                        "name": "Spearphishing Attachment"
                    }
                ]
            },
            status=200
        )

        markdown_content = """
---
name: ICS Rule
matrix: ics
tactics:
  - id: TA0104
    techniques:
      - id: T0865
---
```sql
from logs-* | where server = 'ics'
```
"""
        md_file = self.temp_dir / "ics.md"
        md_file.write_text(markdown_content, encoding='utf-8')

        rules = extract_esql_from_markdown(md_file)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["query"], "from logs-* | where host.name = 'ics'")
        self.assertEqual(rules[0]["meta"]["original_query"], "from logs-* | where server = 'ics'")
        self.assertEqual(rules[0]["threat"][0]["tactic"]["id"], "TA0104")

    def test_validate_ndjson(self):
        ndjson_content = '{"rule_id":"test","name":"Test Rule","query":"from logs-* | where host.name = \'test\'","ecs_version":"9.1.0"}\n'
        ndjson_file = self.temp_dir / "test.ndjson"
        ndjson_file.write_text(ndjson_content, encoding='utf-8')
        self.assertTrue(validate_ndjson(ndjson_file))

    def test_load_config(self):
        config_content = """
kibana_url: https://localhost:5601
api_key: test-key
es_host: https://localhost:9200
es_index: test-index
batch_size: 1000
ca_cert_path: /app/ca.crt
"""
        config_file = self.temp_dir / "config.yaml"
        config_file.write_text(config_content, encoding='utf-8')
        config = load_config(config_file)
        self.assertEqual(config["kibana_url"], "https://localhost:5601")
        self.assertEqual(config["ca_cert_path"], "/app/ca.crt")

    @responses.activate
    def test_import_to_kibana(self):
        ndjson_content = '{"rule_id":"test","name":"Test Rule","query":"from logs-* | where host.name = \'test\'","ecs_version":"9.1.0"}\n'
        ndjson_file = self.temp_dir / "test.ndjson"
        ndjson_file.write_text(ndjson_content, encoding='utf-8')

        responses.add(
            responses.POST,
            "http://localhost:5601/api/saved_objects/_import",
            json={"success": True},
            status=200
        )

        success = import_to_kibana(
            ndjson_file,
            "test.ndjson",
            "http://localhost:5601/api/saved_objects/_import",
            "test-key",
            ca_cert_path=None,
            overwrite=True
        )
        self.assertTrue(success)

if __name__ == '__main__':
    unittest.main()