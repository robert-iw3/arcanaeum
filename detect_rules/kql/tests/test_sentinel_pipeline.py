import pytest
import json
import os
from unittest import mock
from azure.core.exceptions import HttpResponseError
from sentinel_pipeline import SentinelPipeline, KQL_VALIDATION_SUCCESS, KQL_VALIDATION_FAILURES, CACHE_HITS, METADATA_PARSING_ERRORS

@pytest.fixture
def config():
    return {
        "subscription_id": "test-sub-id",
        "resource_group_name": "test-rg",
        "workspace_name": "test-workspace",
        "location": "eastus2",
        "query_pack_name": "TestQueryPack"
    }

@pytest.fixture
def pipeline(config):
    return SentinelPipeline(config, cache_ttl=60, batch_size=2)

@pytest.fixture
def valid_kql(tmp_path):
    kql_content = """// Name: Test Query
// Description: This is a valid test query
// Tags: test, hunting
let timeframe = 1h;
DeviceEvents | where TimeGenerated > ago(timeframe) | top 10 by TimeGenerated
"""
    kql_file = tmp_path / "valid_query.kql"
    kql_file.write_text(kql_content)
    return kql_file

@pytest.fixture
def multiline_kql(tmp_path):
    kql_content = """// Name: Multi-line Query
// Description: This is line 1
// of a multi-line description
// Tags: test, hunting
let timeframe = 1h;
DeviceEvents | where TimeGenerated > ago(timeframe)
"""
    kql_file = tmp_path / "multiline_query.kql"
    kql_file.write_text(kql_content)
    return kql_file

@pytest.fixture
def invalid_kql_empty(tmp_path):
    kql_content = """// Name: Empty Query
// Description: This query is empty
"""
    kql_file = tmp_path / "empty_query.kql"
    kql_file.write_text(kql_content)
    return kql_file

@pytest.fixture
def invalid_kql_no_time(tmp_path):
    kql_content = """// Name: No Time Filter
// Description: Missing time filter
DeviceEvents | where ActionType == "Test"
"""
    kql_file = tmp_path / "no_time_query.kql"
    kql_file.write_text(kql_content)
    return kql_file

@pytest.fixture
def invalid_kql_deprecated(tmp_path):
    kql_content = """// Name: Deprecated Query
// Description: Uses deprecated operator
search * contains "test"
"""
    kql_file = tmp_path / "deprecated_query.kql"
    kql_file.write_text(kql_content)
    return kql_file

@pytest.fixture
def invalid_kql_syntax(tmp_path):
    kql_content = """// Name: Syntax Error
// Description: Invalid syntax
let timeframe = 1h
DeviceEvents | where TimeGenerated > ago(timeframe
"""
    kql_file = tmp_path / "syntax_error_query.kql"
    kql_file.write_text(kql_content)
    return kql_file

@pytest.fixture
def invalid_kql_malicious(tmp_path):
    kql_content = """// Name: Malicious Query
// Description: Contains malicious pattern
DeviceEvents | where TimeGenerated > ago(1h) | execute "powershell"
"""
    kql_file = tmp_path / "malicious_query.kql"
    kql_file.write_text(kql_content)
    return kql_file

def test_validate_config(config):
    pipeline = SentinelPipeline(config)
    assert pipeline.config == {k: str(v) for k, v in config.items()}
    invalid_config = config.copy()
    invalid_config["subscription_id"] = None
    with pytest.raises(ValueError, match="Missing configuration"):
        SentinelPipeline(invalid_config)

def test_parse_kql_file(pipeline, valid_kql):
    metadata, query, tags = pipeline.parse_kql_file(str(valid_kql))
    assert metadata["displayName"] == "Test Query"
    assert metadata["description"] == "This is a valid test query"
    assert tags["Tags"] == ["test", "hunting"]
    assert "DeviceEvents" in query
    assert str(valid_kql) in pipeline.kql_cache
    assert CACHE_HITS._value.get() == 0
    pipeline.parse_kql_file(str(valid_kql))
    assert CACHE_HITS._value.get() == 1

def test_parse_multiline_metadata(pipeline, multiline_kql):
    metadata, query, tags = pipeline.parse_kql_file(str(multiline_kql))
    assert metadata["displayName"] == "Multi-line Query"
    assert metadata["description"] == "This is line 1 of a multi-line description"
    assert tags["Tags"] == ["test", "hunting"]
    assert "DeviceEvents" in query

def test_validate_kql_query_valid(pipeline, valid_kql):
    _, query, _ = pipeline.parse_kql_file(str(valid_kql))
    is_valid, message = pipeline.validate_kql_query(query, str(valid_kql))
    assert is_valid
    assert message == "Valid KQL query"
    assert KQL_VALIDATION_SUCCESS.labels(rule="all")._value.get() > 0

def test_validate_kql_query_empty(pipeline, invalid_kql_empty):
    _, query, _ = pipeline.parse_kql_file(str(invalid_kql_empty))
    is_valid, message = pipeline.validate_kql_query(query, str(invalid_kql_empty))
    assert not is_valid
    assert message == "Query is empty"
    assert KQL_VALIDATION_FAILURES.labels(rule="empty_query")._value.get() > 0

def test_validate_kql_query_no_time_filter(pipeline, invalid_kql_no_time):
    _, query, _ = pipeline.parse_kql_file(str(invalid_kql_no_time))
    is_valid, message = pipeline.validate_kql_query(query, str(invalid_kql_no_time))
    assert not is_valid
    assert "time filter" in message
    assert KQL_VALIDATION_FAILURES.labels(rule="time_filter")._value.get() > 0

def test_validate_kql_query_deprecated(pipeline, invalid_kql_deprecated):
    _, query, _ = pipeline.parse_kql_file(str(invalid_kql_deprecated))
    is_valid, message = pipeline.validate_kql_query(query, str(invalid_kql_deprecated))
    assert not is_valid
    assert "deprecated operators" in message
    assert KQL_VALIDATION_FAILURES.labels(rule="no_deprecated")._value.get() > 0

def test_validate_kql_query_syntax_error(pipeline, invalid_kql_syntax):
    with pytest.raises(ValueError, match="syntax error"):
        pipeline.parse_kql_file(str(invalid_kql_syntax))

def test_validate_kql_query_malicious(pipeline, invalid_kql_malicious):
    _, query, _ = pipeline.parse_kql_file(str(invalid_kql_malicious))
    is_valid, message = pipeline.validate_kql_query(query, str(invalid_kql_malicious))
    assert not is_valid
    assert "malicious patterns" in message
    assert KQL_VALIDATION_FAILURES.labels(rule="no_malicious")._value.get() > 0

def test_oversized_metadata(pipeline, tmp_path):
    oversized_kql = """// Name: Test Query
// Description: {}
let timeframe = 1h;
DeviceEvents | where TimeGenerated > ago(timeframe)
""".format("x" * 1500)
    kql_file = tmp_path / "oversized_query.kql"
    kql_file.write_text(oversized_kql)
    with pytest.raises(ValueError, match="Metadata exceeds 1KB limit"):
        pipeline.parse_kql_file(str(kql_file))
    assert METADATA_PARSING_ERRORS.labels(file=str(kql_file))._value.get() > 0

def test_oversized_query(pipeline, tmp_path):
    oversized_kql = """// Name: Oversized Query
// Description: Valid query
let timeframe = 1h;
DeviceEvents | where TimeGenerated > ago(timeframe) | summarize count() by {}
""".format("x" * 10000)
    kql_file = tmp_path / "oversized_query.kql"
    kql_file.write_text(oversized_kql)
    _, query, _ = pipeline.parse_kql_file(str(kql_file))
    is_valid, message = pipeline.validate_kql_query(query, str(kql_file))
    assert not is_valid
    assert "exceeds 10KB" in message
    assert KQL_VALIDATION_FAILURES.labels(rule="query_too_long")._value.get() > 0

def test_create_query_resource_json(pipeline, valid_kql):
    metadata, query, tags = pipeline.parse_kql_file(str(valid_kql))
    resource = pipeline.create_query_resource_json(metadata, query, tags)
    assert resource["type"] == "queries"
    assert resource["properties"]["displayName"] == "Test Query"
    assert resource["properties"]["description"] == "This is a valid test query"
    assert resource["properties"]["related"]["categories"] == ["Hunting Queries"]
    assert "DeviceEvents" in resource["properties"]["body"]

def test_create_arm_template(pipeline, valid_kql):
    metadata, query, tags = pipeline.parse_kql_file(str(valid_kql))
    query_resource = pipeline.create_query_resource_json(metadata, query, tags)
    arm_template = pipeline.create_arm_template(query_resource)
    assert arm_template["$schema"].endswith("deploymentTemplate.json#")
    assert len(arm_template["resources"]) == 1
    assert arm_template["resources"][0]["name"] == pipeline.config["query_pack_name"]

@mock.patch('sentinel_pipeline.LogAnalyticsManagementClient')
@mock.patch('sentinel_pipeline.ResourceManagementClient')
def test_check_or_create_workspace(mock_resource_client, mock_log_analytics_client, pipeline):
    mock_log_analytics_client.workspaces.get.side_effect = mock.Mock(side_effect=HttpResponseError("Not found", status_code=404))
    mock_resource_client.resource_groups.check_existence.return_value = False
    assert pipeline.check_or_create_workspace()
    mock_resource_client.resource_groups.create_or_update.assert_called_once()
    mock_log_analytics_client.workspaces.begin_create_or_update.assert_called_once()

@mock.patch('sentinel_pipeline.LogAnalyticsManagementClient')
def test_import_query_retry_throttling(mock_log_analytics_client, pipeline, tmp_path):
    mock_log_analytics_client.saved_searches.create_or_update.side_effect = [HttpResponseError("Rate limit", status_code=429), None]
    json_content = {
        "resources": [{
            "resources": [{
                "properties": {
                    "displayName": "Test Query",
                    "body": "DeviceEvents | where TimeGenerated > ago(1h)"
                }
            }]
        }]
    }
    json_file = tmp_path / "test.json"
    with open(json_file, 'w') as f:
        json.dump(json_content, f)
    assert pipeline.import_query(str(json_file))
    assert mock_log_analytics_client.saved_searches.create_or_update.call_count == 2

def test_batch_processing(pipeline, tmp_path):
    kql_content = """// Name: Test Query {}
// Description: Test query
let timeframe = 1h;
DeviceEvents | where TimeGenerated > ago(timeframe)
"""
    for i in range(3):
        kql_file = tmp_path / f"query_{i}.kql"
        kql_file.write_text(kql_content.format(i))
    json_files = pipeline.process_directory(str(tmp_path))
    assert len(json_files) == 3
    for json_file in json_files:
        assert json_file.endswith(".json")
        assert os.path.exists(json_file)