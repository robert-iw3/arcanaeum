#!/bin/bash

# --- Configuration ---
KIBANA_URL="https://your_kibana_url:5601"
KIBANA_API_KEY="<your_encoded_api_key>"
ADCS_SERVER_IPS=(
    "192.168.1.55"
    "192.168.1.56"
)

# --- Script starts here ---

# Function to check if a command was successful
check_success() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed."
        exit 1
    fi
}

echo "Step 1: Creating the shared exception list container for AD CS servers."
RESPONSE=$(curl -s -X POST "$KIBANA_URL/api/exception_lists" \
-H 'kbn-xsrf: true' \
-H 'Content-Type: application/json' \
-H "Authorization: ApiKey $KIBANA_API_KEY" \
--insecure \
-d '{
  "id": "adcs_servers",
  "name": "AD CS Servers",
  "namespace_type": "single",
  "description": "Exempts the IP addresses of known AD CS servers for NTLM relay detection."
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

echo "Step 2: Adding AD CS server IPs to the exception list."
for ip in "${ADCS_SERVER_IPS[@]}"; do
    echo "Adding IP: $ip"
    ITEM_RESPONSE=$(curl -s -X POST "$KIBANA_URL/api/exception_lists/items" \
    -H 'kbn-xsrf: true' \
    -H 'Content-Type: application/json' \
    -H "Authorization: ApiKey $KIBANA_API_KEY" \
    --insecure \
    -d '{
      "list_id": "'"$LIST_ID"'",
      "entry_type": "simple",
      "fields": [
        {
          "field": "source.ip",
          "value": "'"$ip"'"
        }
      ]
    }')
    check_success "Adding list item for $ip"
    echo "$ITEM_RESPONSE" | jq .
done
echo "---------------------------------------------------"
echo "Exception list and items created successfully."
