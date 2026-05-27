#!/bin/bash
set -euo pipefail

# Authenticates with Azure and runs the Sentinel KQL import pipeline.
#
# Prerequisites:
# - Environment variables: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID,
#   SUBSCRIPTION_ID, RESOURCE_GROUP_NAME, WORKSPACE_NAME, AZURE_LOCATION, QUERY_PACK_NAME
# - Permissions: Log Analytics Contributor on the target workspace
# - az CLI and Python with requirements.txt installed

# Validate environment variables
required_vars=("AZURE_CLIENT_ID" "AZURE_CLIENT_SECRET" "AZURE_TENANT_ID" "SUBSCRIPTION_ID" "RESOURCE_GROUP_NAME" "WORKSPACE_NAME")
for var in "${required_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "{\"event\": \"validation_failed\", \"variable\": \"$var\", \"error\": \"Missing environment variable\"}"
    exit 1
  fi
done

# Run static code analysis
echo "{\"event\": \"static_analysis\"}"
python3 -m flake8 sentinel_pipeline.py tests/ --max-line-length=120 || {
  echo "{\"event\": \"static_analysis_failed\", \"error\": \"Code style issues detected\"}"
  exit 1
}

# Lint KQL files
echo "{\"event\": \"kql_linting\"}"
for file in $(find . -name "*.kql"); do
  if ! grep -q "TimeGenerated" "$file"; then
    echo "{\"event\": \"kql_lint_failed\", \"file\": \"$file\", \"error\": \"Missing TimeGenerated filter\"}"
    exit 1
  fi
  if grep -qi "search" "$file"; then
    echo "{\"event\": \"kql_lint_failed\", \"file\": \"$file\", \"error\": \"Contains deprecated 'search' operator\"}"
    exit 1
  fi
done

# Retry Azure login
for attempt in {1..3}; do
  echo "{\"event\": \"azure_login_attempt\", \"attempt\": $attempt}"
  az login --service-principal \
    --username "${AZURE_CLIENT_ID}" \
    --password "${AZURE_CLIENT_SECRET}" \
    --tenant "${AZURE_TENANT_ID}" > /dev/null && break
  if [ $attempt -eq 3 ]; then
    echo "{\"event\": \"azure_login_failed\", \"error\": \"Authentication failed after 3 attempts\"}"
    exit 1
  fi
  sleep $((2 ** attempt))
done
echo "{\"event\": \"azure_login_success\"}"

# Set subscription
az account set --subscription "${SUBSCRIPTION_ID}" || {
  echo "{\"event\": \"set_subscription_failed\", \"error\": \"Failed to set subscription\"}"
  exit 1
}

# Run pipeline
echo "{\"event\": \"starting_pipeline\"}"
python3 sentinel_pipeline.py || {
  echo "{\"event\": \"pipeline_failed\", \"error\": \"Check sentinel_pipeline.log for details\"}"
  exit 1
}

echo "{\"event\": \"pipeline_completed\", \"metrics\": \"http://localhost:8000\"}"