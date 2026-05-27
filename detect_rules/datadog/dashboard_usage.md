# Grafana Dashboard Usage for Datadog Rule Import Pipeline

This guide provides setup and usage instructions for the Grafana dashboard (`datadog_pipeline_dashboard.json`) to monitor the Datadog rule import pipeline. The dashboard visualizes metrics from `test_metrics.json`, `conversion_metrics.json`, and `coverage.json`, including success rates, execution times, test coverage, and failure reasons, using Prometheus and (optionally) Loki.

## Prerequisites
- **Grafana**: Installed and accessible (e.g., `http://grafana:3000`).
- **Prometheus**: Pushgateway configured (e.g., `pushgateway:9091`).
- **Loki** (optional): For exploring failure reasons (e.g., `loki:3100`).
- **Pipeline Outputs**: `test_metrics.json`, `conversion_metrics.json`, `coverage.json` from `datadog_rule_converter.py` and `test_datadog_rule_conversion.py`.
- **GitHub Secrets**: `PROMETHEUS_GATEWAY` (optional), `SLACK_BOT_TOKEN` for notifications.
- **Dependencies**: `jq` for parsing JSON in GitHub Actions.

## Setup Instructions

### 1. Configure Prometheus Pushgateway
- **Update Prometheus Config**:
  Add the pushgateway to `prometheus.yml`:
  ```yaml
  scrape_configs:
    - job_name: 'datadog_pipeline'
      static_configs:
        - targets: ['pushgateway:9091']
  ```
- **Restart Prometheus**:
  ```bash
  docker restart prometheus
  ```
- **Add Prometheus Data Source in Grafana**:
  - Go to Grafana > “Configuration” > “Data Sources” > “Add data source”.
  - Select “Prometheus”, set URL (e.g., `http://prometheus:9090`), and save.

### 2. Configure Loki (Optional)
- **Set Up Loki**:
  Ensure Loki is running (e.g., `loki:3100`).
- **Add Loki Data Source in Grafana**:
  - Go to Grafana > “Configuration” > “Data Sources” > “Add data source”.
  - Select “Loki”, set URL (e.g., `http://loki:3100`), and save.

### 3. Enable Metrics Push in GitHub Actions
- **Update Workflow**:
  In `.github/workflows/datadog_rule_import.yml`, uncomment and configure the “Push Test Metrics to Prometheus” step:
  ```yaml
  - name: Push Test Metrics to Prometheus
    if: always()
    env:
      PROMETHEUS_GATEWAY: ${{ secrets.PROMETHEUS_GATEWAY }}
    run: |
      if [ -f test_metrics.json ] && [ -f conversion_metrics.json ]; then
        total_files=$(jq '.total_files' test_metrics.json)
        files_passed=$(jq '.files_passed' test_metrics.json)
        files_failed=$(jq '.files_failed' test_metrics.json)
        total_rules=$(jq '.total_rules' test_metrics.json)
        rules_passed=$(jq '.rules_passed' test_metrics.json)
        rules_failed=$(jq '.rules_failed' test_metrics.json)
        test_duration=$(jq '.test_duration_seconds' test_metrics.json)
        coverage_percentage=$(jq '.coverage_percentage' test_metrics.json)
        conv_total_files=$(jq '.total_files' conversion_metrics.json)
        conv_files_processed=$(jq '.files_processed' conversion_metrics.json)
        conv_files_failed=$(jq '.files_failed' conversion_metrics.json)
        conv_total_rules=$(jq '.total_rules' conversion_metrics.json)
        conv_rules_processed=$(jq '.rules_processed' conversion_metrics.json)
        conv_rules_failed=$(jq '.rules_failed' conversion_metrics.json)
        conv_duration=$(jq '.conversion_duration_seconds' conversion_metrics.json)
        curl -X POST --data-binary \
          "test_files_total $total_files\n\
          test_files_passed $files_passed\n\
          test_files_failed $files_failed\n\
          test_rules_total $total_rules\n\
          test_rules_passed $rules_passed\n\
          test_rules_failed $rules_failed\n\
          test_duration_seconds $test_duration\n\
          test_coverage_percentage $coverage_percentage\n\
          total_files $conv_total_files\n\
          files_processed $conv_files_processed\n\
          files_failed $conv_files_failed\n\
          total_rules $conv_total_rules\n\
          rules_processed $conv_rules_processed\n\
          rules_failed $conv_rules_failed\n\
          conversion_duration_seconds $conv_duration" \
          $PROMETHEUS_GATEWAY
      fi
  ```
- **Add Secret**:
  In GitHub, go to “Settings” > “Secrets and variables” > “Actions” > “New repository secret”, add `PROMETHEUS_GATEWAY` (e.g., `http://pushgateway:9091`).

### 4. Push Logs to Loki (Optional)
- **Manual Push**:
  ```bash
  curl -X POST -H "Content-Type: application/json" \
    --data-binary @test_metrics.json \
    http://loki:3100/loki/api/v1/push
  curl -X POST -H "Content-Type: application/json" \
    --data-binary @conversion_metrics.json \
    http://loki:3100/loki/api/v1/push
  ```
- **Automate in Workflow** (optional):
  Add to `datadog_rule_import.yml`:
  ```yaml
  - name: Push Logs to Loki
    if: always()
    env:
      LOKI_ENDPOINT: ${{ secrets.LOKI_ENDPOINT }}
    run: |
      if [ -f test_metrics.json ]; then
        curl -X POST -H "Content-Type: application/json" \
          --data-binary @test_metrics.json \
          $LOKI_ENDPOINT
      fi
      if [ -f conversion_metrics.json ]; then
        curl -X POST -H "Content-Type: application/json" \
          --data-binary @conversion_metrics.json \
          $LOKI_ENDPOINT
      fi
  ```
  Add `LOKI_ENDPOINT` (e.g., `http://loki:3100/loki/api/v1/push`) to GitHub Secrets.

### 5. Import Grafana Dashboard
- **Save Dashboard**:
  Copy the `datadog_pipeline_dashboard.json` content to a file (e.g., `datadog_pipeline_dashboard.json`).
- **Import to Grafana**:
  - Go to Grafana > “Dashboards” > “Import”.
  - Upload `datadog_pipeline_dashboard.json` or paste its content.
  - Select the Prometheus data source (and Loki if configured).
  - Save with name “Datadog Rule Import Pipeline Dashboard”.

### 6. Run Pipeline and Verify
- **Run Pipeline**:
  ```bash
  python test_datadog_rule_conversion.py  # Generate test_metrics.json, coverage.json
  python datadog_rule_converter.py  # Generate conversion_metrics.json
  ```
  Or trigger via GitHub Actions (push, pull request, or scheduled).
- **Verify Metrics**:
  - Check `test_metrics.json`, `conversion_metrics.json`, `coverage.json` in the repository.
  - In Prometheus (`http://prometheus:9090`), query metrics (e.g., `test_files_total`, `test_coverage_percentage`).
  - In Loki (`http://loki:3100`), query `{job="datadog_rule_tests"} | json | failure_reasons!=null` for failure reasons.
- **View Dashboard**:
  - Open Grafana, navigate to the dashboard.
  - Verify panels:
    - **Pipeline Success Rates (%)**: Test and conversion success rates (e.g., 80%).
    - **Pipeline Execution Times (seconds)**: Test and conversion durations (e.g., 0.123s, 0.456s).
    - **Test Coverage (%)**: Coverage percentage (e.g., 85%, green if >90%).
    - **Failed Files**: Number of failed test/conversion files (e.g., 2).
    - **Failure Reasons (Loki)**: Detailed failure logs (e.g., “Unbalanced parentheses”).

## Dashboard Features
- **Panels**:
  - **Pipeline Success Rates (%)**: Timeseries of test and conversion success rates (`files_passed/total_files`, `files_processed/total_files`).
  - **Pipeline Execution Times (seconds)**: Timeseries of `test_duration_seconds` and `conversion_duration_seconds`.
  - **Test Coverage (%)**: Bar chart of `test_coverage_percentage` (green >90%, yellow >80%, red <80%).
  - **Failed Files**: Bar chart of `test_files_failed` and `files_failed`.
  - **Failure Reasons (Loki)**: Log panel for `failure_reasons` from JSON metrics.
- **Metrics**:
  - From `test_metrics.json`: `total_files`, `files_passed`, `files_failed`, `total_rules`, `rules_passed`, `rules_failed`, `test_duration_seconds`, `coverage_percentage`.
  - From `conversion_metrics.json`: `total_files`, `files_processed`, `files_failed`, `total_rules`, `rules_processed`, `rules_failed`, `conversion_duration_seconds`.
- **Alerts** (optional):
  - Set thresholds in Grafana (e.g., alert if `test_coverage_percentage` <80% or `test_files_failed` >0).

## Troubleshooting
- **No Data in Dashboard**:
  - Verify Prometheus pushgateway is running and accessible.
  - Check `PROMETHEUS_GATEWAY` in GitHub Secrets.
  - Ensure pipeline generates `test_metrics.json`, `conversion_metrics.json`, `coverage.json`.
  - Query Prometheus (e.g., `test_files_total`) to confirm metrics.
- **Loki Logs Missing**:
  - Verify `LOKI_ENDPOINT` and push commands.
  - Check Loki query `{job="datadog_rule_tests"}`.
- **Dashboard Errors**:
  - Ensure Prometheus and Loki data sources are correctly configured in Grafana.
  - Verify `datadog_pipeline_dashboard.json` is imported with correct data source names.
- **Low Coverage**:
  - Check `coverage.json` and `test_metrics.json` for `coverage_percentage`.
  - Add more tests in `test_datadog_rule_conversion.py` if below 80%.

## Example Metrics
```json
{
  "total_files": 6,
  "files_passed": 4,
  "files_failed": 2,
  "total_rules": 5,
  "rules_passed": 5,
  "rules_failed": 0,
  "case_counts": {
    "rules/hashicorp_vault_0day_detections.md": 5,
    "rules/linux_persistence_common_TTPs.md": 2
  },
  "failure_reasons": [
    {"file": "rules/subdir/empty_file.md", "reason": "No valid rules parsed"},
    {"file": "rules/subdir/invalid_query.md", "reason": "Query missing 'source:' prefix"}
  ],
  "test_duration_seconds": 0.123,
  "coverage_percentage": 85.0
}
```

For further customization (e.g., alerts, additional panels), refer to Grafana documentation or update `datadog_pipeline_dashboard.json`.