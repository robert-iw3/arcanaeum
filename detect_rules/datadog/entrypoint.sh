#!/bin/bash
set -e

# Ensure directories exist
mkdir -p /app/rules /app/signal_correlation_rules
chown -R appuser:appgroup /app/rules /app/signal_correlation_rules

# Validate DD_DRY_RUN
if [ "$DD_DRY_RUN" != "true" ] && [ "$DD_DRY_RUN" != "false" ]; then
    echo "Invalid DD_DRY_RUN: $DD_DRY_RUN. Use 'true' or 'false'."
    exit 1
fi

# Select script based on DD_SCRIPT
case "$DD_SCRIPT" in
    convert)
        exec python3 /app/datadog_rule_converter.py
        ;;
    import)
        exec python3 /app/import_rules.py
        ;;
    test)
        exec python3 /app/datadog_rule_converter.py test
        ;;
    *)
        echo "Invalid DD_SCRIPT: $DD_SCRIPT. Use 'convert', 'import', or 'test'."
        exit 1
        ;;
esac