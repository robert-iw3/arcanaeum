### Import .json Rules
---

https://docs.datadoghq.com/api/latest/security-monitoring/

### Single Rule Example
---

Replace <DATADOG_API_KEY> and <DATADOG_APP_KEY> with your actual keys.

```bash
curl -X POST "https://api.datadoghq.com/api/v2/security_monitoring/rules" \
-H "Content-Type: application/json" \
-H "DD-API-KEY: <DATADOG_API_KEY>" \
-H "DD-APPLICATION-KEY: <DATADOG_APP_KEY>" \
--data-binary "<RULE_NAME>.json"
```

### Bulk Batch Shell Script
---

`datadog_rule_import.sh`

```bash
#!/usr/bin/env bash

DATADOG_API_KEY=
DATADOG_APP_KEY=

declare -a RULE_NAME=(
"some_rule1.json"
"some_rule2.json"
"some_rule3.json"
"some_rule4.json"
"some_rule5.json"
"some_rule6.json"
"some_rule7.json"
"some_rule8.json"
"some_rule9.json"
"some_rule10.json"
"some_rule11.json"
"some_rule12.json"
"some_rule13.json"
)

for ((i=0; i<${#RULE_NAME[@]}; i++)); do
    curl -X POST "https://api.datadoghq.com/api/v2/security_monitoring/rules" \
        -H "Content-Type: application/json" \
        -H "DD-API-KEY: ${DATADOG_API_KEY}" \
        -H "DD-APPLICATION-KEY: ${DATADOG_APP_KEY}" \
        --data-binary "@${RULE_NAME[$i]}.json"
done

# confirm upload
curl -X GET "https://api.datadoghq.com/api/v2/security_monitoring/rules?is_default=false" \
    -H "Accept: application/json" \
    -H "DD-API-KEY: ${DATADOG_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DATADOG_APP_KEY}"
```