# Datadog Rule Import Pipeline

Automates conversion of Markdown/YAML signal correlation rules in `rules/` and subdirectories to JSON and imports them to Datadog. Dynamically processes all `.md`, `.yaml`, and `.yml` files with parallel processing, using rule names for JSON filenames and handling duplicates with suffixes (e.g., `_2`). Includes unit tests with deep query validation, test coverage, and metrics logging for DevOps pipelines (e.g., Grafana).

## Quick Start

### Prerequisites
- Python 3.10+
- Docker (optional)
- Datadog API/App keys
- GitHub repository with Secrets
- Prometheus Pushgateway and/or Loki for Grafana (optional)
- Markdown/YAML rules in `rules/` and subdirectories

### Setup
1. **Clone Repository**:
   ```bash
   git clone <repository-url>
   cd <repository>
   ```

2. **Install Dependencies**:
   ```bash
   pip install pyyaml==6.0.2 datadog-api-client==2.25.0 urllib3==2.2.3 jsonschema==4.23.0 coverage==7.6.1
   ```

3. **Directory Structure**:
   ```
   .
   ├── datadog_rule_converter.py  # Parallel processing, mock query executor
   ├── test_datadog_rule_conversion.py  # Validates rules with coverage
   ├── import_rules.py
   ├── Dockerfile
   ├── entrypoint.sh
   ├── .github/workflows/datadog_rule_import.yml
   ├── rules/
   │   ├── misc-detection-rules.md  # Multiple ```yaml``` blocks
   │   ├── hashicorp_vault_0day_detections.md  # Multiple ```sql``` blocks
   │   ├── linux_persistence_common_TTPs.md  # Multiple ```sql``` blocks
   │   ├── critical_infra_attacks_irgc.md  # Single ```sql``` block
   │   ├── subdir/
   │   │   ├── example.yaml
   │   │   ├── another_rule.md
   ├── signal_correlation_rules/
   │   ├── sqli_detection.json
   │   ├── hashicorp_vault_0day_detections.json
   ├── test_metrics.json  # Unit test metrics for Grafana
   ├── conversion_metrics.json  # Conversion metrics for Grafana
   ├── coverage.json  # Test coverage metrics
   ```

4. **Configure Environment**:
   ```bash
   export DD_API_KEY=<your-api-key>
   export DD_APP_KEY=<your-app-key>
   export DD_SITE=us
   export DD_DRY_RUN=false
   ```

5. **GitHub Actions**:
   - Add `DD_API_KEY`, `DD_APP_KEY`, `SLACK_BOT_TOKEN`, `PROMETHEUS_GATEWAY` (optional) to GitHub Secrets.
   - Runs on push, pull requests, or daily.

6. **Grafana Setup**:
   - **Prometheus**:
     - Configure a Prometheus Pushgateway (e.g., `pushgateway:9091`).
     - Update `prometheus.yml`:
       ```yaml
       scrape_configs:
         - job_name: 'datadog_pipeline'
           static_configs:
             - targets: ['pushgateway:9091']
       ```
     - Add Prometheus data source in Grafana.
   - **Loki (Optional)**:
     - Configure Loki (e.g., `loki:3100`).
     - Add Loki data source in Grafana.
   - **Import Dashboard**:
     - Save `datadog_pipeline_dashboard.json` (provided separately).
     - In Grafana, go to “Dashboards” > “Import”, upload the JSON, select Prometheus and Loki data sources.
   - **Push Metrics**:
     - Uncomment the “Push Test Metrics to Prometheus” step in `datadog_rule_import.yml`.
     - For Loki, push JSON logs:
       ```bash
       curl -X POST -H "Content-Type: application/json" \
         --data-binary @test_metrics.json \
         http://loki:3100/loki/api/v1/push
       curl -X POST -H "Content-Type: application/json" \
         --data-binary @conversion_metrics.json \
         http://loki:3100/loki/api/v1/push
       ```

### Usage

| Script                  | Purpose                                      |
|-------------------------|----------------------------------------------|
| `datadog_rule_converter.py` | Converts all Markdown/YAML/SQL in `rules/` to JSON (parallelized), validates queries, imports to Datadog |
| `test_datadog_rule_conversion.py` | Validates conversion of all `rules/` files, logs metrics and coverage in `test_metrics.json`, `coverage.json` |
| `import_rules.py`       | Imports JSONs from `signal_correlation_rules/` |

1. **Local Run**:
   ```bash
   coverage run --source=. --omit="*/test_*.py" test_datadog_rule_conversion.py  # Validate rules, generate coverage.json
   coverage json -o coverage.json
   python datadog_rule_converter.py  # Convert and import all rules (parallelized)
   python import_rules.py           # Import only
   python datadog_rule_converter.py test  # Run converter tests
   export DD_DRY_RUN=true; python datadog_rule_converter.py  # Dry-run mode
   ```
   - Outputs: `conversion_summary.json`, `import_summary.json`, `signal_correlation_rules/<rule_name>.json`, `test_metrics.json`, `conversion_metrics.json`, `coverage.json`
   - Processes all `.md`, `.yaml`, `.yml` files in `rules/` using parallel threads.
   - Query validation checks known sources (e.g., `vault`), field references, operators, aggregations.

2. **Docker Run**:
   ```bash
   docker build -t datadog-rule-importer .
   docker run --rm -v $(pwd)/rules:/app/rules -v $(pwd)/signal_correlation_rules:/app/signal_correlation_rules \
     -e DD_API_KEY=<your-api-key> -e DD_APP_KEY=<your-app-key> \
     datadog-rule-importer
   ```
   - For import only: `-e DD_SCRIPT=import`
   - For converter tests: `-e DD_SCRIPT=test`
   - For validation tests: `-e DD_SCRIPT=test_conversion`
   - For dry-run: `-e DD_DRY_RUN=true`

3. **GitHub Actions**:
   - Validates all rules with coverage.
   - Runs dry-run and full conversion/import.
   - Uploads summaries, JSONs, `test_metrics.json`, `conversion_metrics.json`, `coverage.json` as artifacts.
   - Check Slack `security-alerts` for status.

4. **Grafana Dashboard**:
   - Visualizes pipeline metrics in `datadog_pipeline_dashboard.json`:
     - Success rates (test/conversion files).
     - Execution times (test/conversion durations).
     - Test coverage percentage.
     - Failed files count.
     - Failure reasons (via Loki).
   - Metrics: `total_files`, `files_passed`, `files_failed`, `total_rules`, `rules_passed`, `rules_failed`, `test_duration_seconds`, `conversion_duration_seconds`, `coverage_percentage`.

### Example Markdown
```markdown
# Rule with SQL Query
```yaml
name: CloudTrail Error
type: signal_correlation
signal_correlation:
  group_by_fields:
    - host
  distinct_fields:
    - case_id
  correlation:
    expression: distinct_count >= 1
    timeframe: 1h
message: Detects errors in CloudTrail
severity: high
tags:
  - security:attack
options:
  evaluation_window: 1h
```
```sql
source:cloudtrail error
```
```

### Troubleshooting
- **Logs**: Check `datadog_rule_conversion.log`, `datadog_import.log`, `test_metrics.json`, `conversion_metrics.json`, `coverage.json`.
- **Errors**: Verify API keys, YAML/SQL syntax, `DD_SITE` (us, eu, etc.).
- **YAML/SQL Blocks**: Ensure ```yaml``` blocks have `name`, `type`; ```sql``` blocks start with `source:`, use valid fields/operators.
- **Query Validation**: Tests check known sources, field references, operators, aggregations, balanced parentheses/quotes, non-empty clauses.
- **Dry-Run**: Use `DD_DRY_RUN=true` to preview without writing files or importing.
- **Tests**: Run `test_datadog_rule_conversion.py` with coverage to validate rules.
- **Coverage**: Check `coverage.json` for test coverage (e.g., 85% line coverage).
- **Grafana**: Verify Prometheus/Loki data sources; check `test_coverage_percentage` <80% for alerts.