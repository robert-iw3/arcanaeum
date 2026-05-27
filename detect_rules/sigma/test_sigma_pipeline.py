import unittest
import yaml
import re
from sigma_pipeline import SigmaRuleValidator, SigmaImporter
from pathlib import Path
import tempfile
import os
from unittest.mock import AsyncMock, patch
import asyncio
from testcontainers.opensearch import OpenSearchContainer
from botocore.exceptions import ClientError

class TestSigmaPipeline(unittest.TestCase):
    """Unit tests for Sigma pipeline components."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'aws_logsource_products': ['windows', 'cloudtrail'],
            'valid_tag_prefixes': ['attack.', 'threat_']
        }
        self.validator = SigmaRuleValidator(self.config)
        self.importer = SigmaImporter(
            host='localhost', port=9200, scheme='http',
            username=None, password=None, verify_certs=False,
            provider='opensearch', aws_region=None, max_workers=2,
            config_path='test_config.yaml'
        )
        self.aws_importer = SigmaImporter(
            host='opensearch-domain.aws', port=443, scheme='https',
            username=None, password=None, verify_certs=True,
            provider='aws', aws_region='us-east-1', max_workers=2,
            config_path='test_config.yaml'
        )

        self.valid_rule = {
            'title': 'Test Rule',
            'id': '123e4567-e89b-12d3-a456-426614174000',
            'status': 'experimental',
            'description': 'Test description',
            'logsource': {
                'product': 'windows',
                'service': 'security'
            },
            'detection': {
                'selection': {'EventID': 4688},
                'condition': 'selection'
            },
            'tags': ['attack.execution']
        }

        # Create test config file
        with open('test_config.yaml', 'w') as f:
            yaml.safe_dump(self.config, f)

    def tearDown(self):
        """Clean up test config file."""
        if os.path.exists('test_config.yaml'):
            os.unlink('test_config.yaml')

    def test_valid_rule(self):
        """Test validation of a valid Sigma rule."""
        is_valid, error_msg = self.validator.validate_rule(self.valid_rule)
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")

    def test_missing_id(self):
        """Test validation of a rule missing the id field."""
        rule_no_id = self.valid_rule.copy()
        del rule_no_id['id']
        is_valid, error_msg = self.validator.validate_rule(rule_no_id)
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")

    def test_aws_valid_rule(self):
        """Test validation of a valid AWS Sigma rule."""
        is_valid, error_msg = self.validator.validate_rule(self.valid_rule, is_aws=True)
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")

    def test_aws_invalid_logsource(self):
        """Test validation with invalid AWS logsource product."""
        invalid_rule = self.valid_rule.copy()
        invalid_rule['logsource']['product'] = 'invalid'
        is_valid, error_msg = self.validator.validate_rule(invalid_rule, is_aws=True)
        self.assertFalse(is_valid)
        self.assertIn("Invalid logsource product for AWS", error_msg)

    def test_custom_tag_prefix(self):
        """Test validation with custom tag prefix from config."""
        self.config['valid_tag_prefixes'] = ['custom.']
        with open('test_config.yaml', 'w') as f:
            yaml.safe_dump(self.config, f)
        validator = SigmaRuleValidator(self.config)
        rule = self.valid_rule.copy()
        rule['tags'] = ['custom.test']
        is_valid, error_msg = validator.validate_rule(rule, strict_tags=True)
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")

    def test_missing_required_field(self):
        """Test validation with missing required field."""
        invalid_rule = self.valid_rule.copy()
        del invalid_rule['title']
        is_valid, error_msg = self.validator.validate_rule(invalid_rule)
        self.assertFalse(is_valid)
        self.assertIn("title", error_msg)

    def test_invalid_status(self):
        """Test validation with invalid status."""
        invalid_rule = self.valid_rule.copy()
        invalid_rule['status'] = 'invalid'
        is_valid, error_msg = self.validator.validate_rule(invalid_rule)
        self.assertFalse(is_valid)
        self.assertIn("Invalid status", error_msg)

    def test_invalid_uuid(self):
        """Test validation with invalid UUID format."""
        invalid_rule = self.valid_rule.copy()
        invalid_rule['id'] = 'invalid-uuid'
        is_valid, error_msg = self.validator.validate_rule(invalid_rule)
        self.assertFalse(is_valid)
        self.assertIn("Invalid UUID format", error_msg)

    def test_missing_logsource_product(self):
        """Test validation with missing logsource product."""
        invalid_rule = self.valid_rule.copy()
        invalid_rule['logsource'] = {}
        is_valid, error_msg = self.validator.validate_rule(invalid_rule)
        self.assertFalse(is_valid)
        self.assertIn("product", error_msg)

    def test_invalid_detection(self):
        """Test validation with invalid detection structure."""
        invalid_rule = self.valid_rule.copy()
        invalid_rule['detection'] = {}
        is_valid, error_msg = self.validator.validate_rule(invalid_rule)
        self.assertFalse(is_valid)
        self.assertIn("Invalid detection structure", error_msg)

    def test_invalid_condition(self):
        """Test validation with invalid detection condition."""
        invalid_rule = self.valid_rule.copy()
        invalid_rule['detection']['condition'] = 'invalid_condition'
        is_valid, error_msg = self.validator.validate_rule(invalid_rule)
        self.assertFalse(is_valid)
        self.assertIn("Invalid detection condition", error_msg)

    def test_invalid_tags(self):
        """Test validation with invalid tags in strict mode."""
        invalid_rule = self.valid_rule.copy()
        invalid_rule['tags'] = ['invalid.tag']
        is_valid, error_msg = self.validator.validate_rule(invalid_rule, strict_tags=True)
        self.assertFalse(is_valid)
        self.assertIn("Invalid tags", error_msg)

    def test_non_strict_tags(self):
        """Test validation with non-standard tags in non-strict mode."""
        invalid_rule = self.valid_rule.copy()
        invalid_rule['tags'] = ['custom.tag']
        is_valid, error_msg = self.validator.validate_rule(invalid_rule, strict_tags=False)
        self.assertTrue(is_valid)
        self.assertEqual(error_msg, "")

    def test_yaml_file_validation(self):
        """Test validation of a YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(self.valid_rule, f)
            temp_file = f.name

        with open(temp_file, 'r') as f:
            rule_data = yaml.safe_load(f)
            is_valid, error_msg = self.validator.validate_rule(rule_data)
            self.assertTrue(is_valid)
            self.assertEqual(error_msg, "")

        os.unlink(temp_file)

    def test_yaml_file_no_id(self):
        """Test processing a YAML file with missing id."""
        rule_no_id = self.valid_rule.copy()
        del rule_no_id['id']
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(rule_no_id, f)
            temp_file = f.name

        success, rule_id, _, _ = asyncio.run(self.importer.process_yaml_file(Path(temp_file), dry_run=True))
        self.assertTrue(success)
        with open(temp_file, 'r') as f:
            updated_data = yaml.safe_load(f)
            self.assertIn('id', updated_data)
            self.assertTrue(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', updated_data['id']))

        os.unlink(temp_file)

    def test_yaml_file_duplicate_id(self):
        """Test processing a YAML file with duplicate id."""
        rule1 = self.valid_rule.copy()
        rule2 = self.valid_rule.copy()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f1:
            yaml.dump(rule1, f1)
            temp_file1 = f1.name
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f2:
            yaml.dump(rule2, f2)
            temp_file2 = f2.name

        asyncio.run(self.importer.process_yaml_file(Path(temp_file1), dry_run=True))

        success, rule_id, _, _ = asyncio.run(self.importer.process_yaml_file(Path(temp_file2), dry_run=True))
        self.assertTrue(success)
        with open(temp_file2, 'r') as f:
            updated_data = yaml.safe_load(f)
            self.assertNotEqual(updated_data['id'], rule1['id'])
            self.assertTrue(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', updated_data['id']))

        os.unlink(temp_file1)
        os.unlink(temp_file2)

    def test_yaml_file_read_only(self):
        """Test processing a YAML file in read-only mode."""
        rule_no_id = self.valid_rule.copy()
        del rule_no_id['id']
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(rule_no_id, f)
            temp_file = f.name

        success, rule_id, _, _ = asyncio.run(self.importer.process_yaml_file(Path(temp_file), read_only=True))
        self.assertTrue(success)
        with open(temp_file, 'r') as f:
            updated_data = yaml.safe_load(f)
            self.assertNotIn('id', updated_data)

        os.unlink(temp_file)

    def test_yml_file_validation_aws(self):
        """Test validation of a .yml file for AWS OpenSearch."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(self.valid_rule, f)
            temp_file = f.name

        success, rule_id, _, _ = asyncio.run(self.aws_importer.process_yaml_file(Path(temp_file), dry_run=True))
        self.assertTrue(success)
        os.unlink(temp_file)

    @patch('sigma_pipeline.OpenSearch')
    async def test_fetch_existing_ids(self, mock_opensearch):
        """Test fetching existing rule IDs."""
        mock_opensearch.search = AsyncMock(return_value={
            'hits': {'hits': [{'_source': {'rule': {'id': '123e4567-e89b-12d3-a456-426614174000'}}}]}
        })
        existing_ids = await self.importer.fetch_existing_ids()
        self.assertEqual(existing_ids, {'123e4567-e89b-12d3-a456-426614174000'})

    @patch('sigma_pipeline.OpenSearch')
    async def test_check_existing_rule(self, mock_opensearch):
        """Test checking for existing rule."""
        mock_opensearch.search = AsyncMock(return_value={'hits': {'total': {'value': 1}}})
        exists = await self.importer.check_existing_rule("Test Rule", "123e4567-e89b-12d3-a456-426614174000")
        self.assertTrue(exists)

    @patch('sigma_pipeline.OpenSearch')
    async def test_import_rule_bulk(self, mock_opensearch):
        """Test bulk rule import."""
        mock_opensearch.bulk = AsyncMock(return_value=([
            (True, {'create': {'_id': 'rule123'}}),
            (True, {'create': {'_id': 'rule124'}})
        ], []))
        rules = [self.valid_rule, self.valid_rule.copy()]
        file_paths = ["test1.yaml", "test2.yaml"]
        categories = ["windows", "windows"]
        results = await self.importer.import_rules_bulk(rules, file_paths, categories, dry_run=False)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(success for success, _ in results))

    @patch('sigma_pipeline.OpenSearch')
    async def test_import_rule_bulk_dry_run(self, mock_opensearch):
        """Test bulk rule import in dry-run mode."""
        rules = [self.valid_rule, self.valid_rule.copy()]
        file_paths = ["test1.yaml", "test2.yaml"]
        categories = ["windows", "windows"]
        results = await self.importer.import_rules_bulk(rules, file_paths, categories, dry_run=True)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(success for success, _ in results))
        mock_opensearch.bulk.assert_not_called()

    @patch('sigma_pipeline.OpenSearch')
    async def test_import_rule_bulk_failure(self, mock_opensearch):
        """Test bulk rule import with partial failure."""
        mock_opensearch.bulk = AsyncMock(return_value=([
            (True, {'create': {'_id': 'rule123'}}),
            (False, {'create': {'error': 'conflict'}})
        ], [{'error': 'conflict'}]))
        rules = [self.valid_rule, self.valid_rule.copy()]
        file_paths = ["test1.yaml", "test2.yaml"]
        categories = ["windows", "windows"]
        results = await self.importer.import_rules_bulk(rules, file_paths, categories, dry_run=False)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0][0])
        self.assertFalse(results[1][0])

    def test_integration_import(self):
        """Integration test with local OpenSearch container."""
        with OpenSearchContainer() as opensearch:
            importer = SigmaImporter(
                host=opensearch.get_container_host_ip(),
                port=opensearch.get_exposed_port(9200),
                scheme='http',
                username='admin',
                password='admin',
                verify_certs=False,
                provider='opensearch',
                config_path='test_config.yaml'
            )
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                yaml.dump(self.valid_rule, f)
                temp_file = f.name

            success, rule_id, _, _ = asyncio.run(importer.process_yaml_file(Path(temp_file)))
            self.assertTrue(success)
            self.assertEqual(rule_id, self.valid_rule['id'])
            os.unlink(temp_file)

    @patch('boto3.Session')
    async def test_aws_import_rule_failure(self, mock_session):
        """Test AWS rule import with permission error."""
        mock_session.get_credentials.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, "get_credentials"
        )
        with self.assertRaises(ValueError):
            SigmaImporter(
                host='opensearch-domain.aws', port=443, scheme='https',
                username=None, password=None, verify_certs=True,
                provider='aws', aws_region='us-east-1', max_workers=2,
                config_path='test_config.yaml'
            )

    async def test_process_yaml_file_invalid(self):
        """Test processing an invalid YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: content")
            temp_file = f.name

        success, rule_id, _, _ = await self.importer.process_yaml_file(Path(temp_file))
        self.assertFalse(success)
        self.assertEqual(rule_id, "")
        os.unlink(temp_file)

if __name__ == '__main__':
    unittest.main()