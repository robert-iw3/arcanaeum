#!/bin/bash

# --- Configuration ---
KIBANA_URL="https://your_kibana_url:5601"
KIBANA_API_KEY="<your_encoded_api_key>"
DOMAIN_CONTROLLERS_IPS=(
    "192.168.1.50"
    "192.168.1.51"
)

# --- Script starts here ---

# Function to check if a command was successful
check_success() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed."
        exit 1
    fi
}

echo "Step 1: Creating the shared exception list container for domain controllers."
RESPONSE=$(curl -s -X POST "$KIBANA_URL/api/exception_lists" \
-H 'kbn-xsrf: true' \
-H 'Content-Type: application/json' \
-H "Authorization: ApiKey $KIBANA_API_KEY" \
--insecure \
-d '{
  "id": "domain_controllers",
  "name": "Domain Controllers",
  "namespace_type": "single",
  "description": "Exempts the IP addresses of known domain controllers from replication detection rules."
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

echo "Step 2: Adding domain controller IPs to the exception list."
for ip in "${DOMAIN_CONTROLLERS_IPS[@]}"; do
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
