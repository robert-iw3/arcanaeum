import unittest
import yaml
from yara_pipeline import YaraLPipeline
from unittest.mock import patch, MagicMock

class TestYaraLPipeline(unittest.TestCase):
    def setUp(self):
        self.test_config = {
            'chronicle_api_url': 'https://test.backstory.chronicle.security/v2',
            'credentials_file': 'test-service-account.json',
            'auth_scope': 'https://www.googleapis.com/auth/chronicle-backstory',
            'rules_dir': './test_rules',
            'max_workers': 2
        }

    def test_load_config(self):
        with patch('builtins.open', unittest.mock.mock_open(read_data=yaml.dump(self.test_config))):
            pipeline = YaraLPipeline('test_config.yaml')
            self.assertEqual(pipeline.config, self.test_config)

    def test_validate_yaral_rule_valid(self):
        valid_rule = """
        rule test_rule {
            meta:
                author = "Test"
                date = "2025-08-31"
                description = "Test rule"
            events:
                $e.metadata.event_type = "TEST_EVENT"
            condition:
                $e
        }
        """
        pipeline = YaraLPipeline()
        self.assertTrue(pipeline._validate_yaral_rule(valid_rule, "test.yaral"))

    def test_validate_yaral_rule_invalid(self):
        invalid_rule = """
        rule test_rule {
            meta:
                author = "Test"
            events:
                $e.metadata.event_type = "TEST_EVENT"
        }
        """
        pipeline = YaraLPipeline()
        self.assertFalse(pipeline._validate_yaral_rule(invalid_rule, "test.yaral"))

    @patch('google.oauth2.service_account.Credentials')
    def test_get_auth_headers(self, mock_credentials):
        mock_credentials.from_service_account_file.return_value.token = "test_token"
        pipeline = YaraLPipeline()
        pipeline.config = self.test_config
        headers = pipeline._get_auth_headers()
        self.assertEqual(headers['Authorization'], "Bearer test_token")

    @patch('requests.post')
    def test_upload_yaral_rule_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {'ruleId': 'test_rule_123'}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        pipeline = YaraLPipeline()
        pipeline.auth_headers = {'Authorization': 'Bearer test_token', 'Content-Type': 'application/json'}
        result = pipeline._upload_yaral_rule('test.yaral')
        self.assertTrue(result)

    def test_find_yaral_files(self):
        with patch('glob.glob', return_value=['test_rules/rule1.yaral', 'test_rules/rule2.yaral']):
            pipeline = YaraLPipeline()
            pipeline.config = self.test_config
            files = pipeline._find_yaral_files()
            self.assertEqual(len(files), 2)

if __name__ == '__main__':
    unittest.main()