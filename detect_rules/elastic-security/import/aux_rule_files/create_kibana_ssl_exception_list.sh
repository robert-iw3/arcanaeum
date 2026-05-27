#!/bin/bash

# --- Configuration ---
KIBANA_URL="https://your_kibana_url:5601"
KIBANA_API_KEY="<your_encoded_api_key>"
TRUSTED_PROCESSES=(
    "YourInternalUpdater.exe"
    "YourDevTool.exe"
)

# --- Script starts here ---

# Function to check if a command was successful
check_success() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed."
        exit 1
    fi
}

echo "Step 1: Creating the shared exception list container for trusted SSL processes."
RESPONSE=$(curl -s -X POST "$KIBANA_URL/api/exception_lists" \
-H 'kbn-xsrf: true' \
-H 'Content-Type: application/json' \
-H "Authorization: ApiKey $KIBANA_API_KEY" \
--insecure \
-d '{
  "id": "trusted_ssl_processes",
  "name": "Trusted SSL Bypass Processes",
  "namespace_type": "single",
  "description": "Exempts known, legitimate processes from SSL validation bypass detection."
}')
check_success "Exception list creation"
LIST_ID=$(echo "$RESPONSE" | jq -r '.list_id')
if [ "$LIST_ID" == "null" ] || [ -z "$LIST_ID" ]; then
    echo "Error: Failed to create exception list or get its ID."
    echo "Full response: $RESPONSE"
    exit 1
fi
echo "Exception list created successfully with ID: $LIST_ID"
echo "---------------------------------------------------"

echo "Step 2: Adding trusted processes to the exception list."
for process_name in "${TRUSTED_PROCESSES[@]}"; do
    echo "Adding process: $process_name"
    curl -s -X POST "$KIBANA_URL/api/exception_lists/items" \
    -H 'kbn-xsrf: true' \
    -H 'Content-Type: application/json' \
    -H "Authorization: ApiKey $KIBANA_API_KEY" \
    --insecure \
    -d '{
      "list_id": "'"$LIST_ID"'",
      "entry_type": "simple",
      "fields": [
        {
          "field": "process.name",
          "value": "'"$process_name"'"
        }
      ]
    }' | jq .
done
echo "---------------------------------------------------"
echo "Exception list and items created successfully."
