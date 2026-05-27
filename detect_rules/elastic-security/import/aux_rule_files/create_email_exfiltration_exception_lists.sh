#!/bin/bash

# --- Configuration ---
KIBANA_URL="https://your_kibana_url:5601"
KIBANA_API_KEY="<your_encoded_api_key>"
INTERNAL_USERS=(
    "user1@yourcompany.com"
    "user2@yourcompany.com"
)
INTERNAL_DOMAINS=(
    "yourcompany.com"
    "yourcompany.net"
)

# --- Script starts here ---

# Function to check if a command was successful
check_success() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed."
        exit 1
    fi
}

echo "Step 1: Creating the exception list for internal users."
curl -s -X POST "$KIBANA_URL/api/exception_lists" \
-H 'kbn-xsrf: true' \
-H 'Content-Type: application/json' \
-H "Authorization: ApiKey $KIBANA_API_KEY" \
--insecure \
-d '{
  "id": "internal_users",
  "name": "Internal Users",
  "namespace_type": "single",
  "description": "Exempts internal users from email exfiltration detection."
}' | jq .
check_success "Internal users list creation"

echo "Step 2: Creating the exception list for internal domains."
curl -s -X POST "$KIBANA_URL/api/exception_lists" \
-H 'kbn-xsrf: true' \
-H 'Content-Type: application/json' \
-H "Authorization: ApiKey $KIBANA_API_KEY" \
--insecure \
-d '{
  "id": "internal_domains",
  "name": "Internal Domains",
  "namespace_type": "single",
  "description": "Exempts internal domains from email exfiltration detection."
}' | jq .
check_success "Internal domains list creation"

echo "Step 3: Adding internal users to the list."
for user in "${INTERNAL_USERS[@]}"; do
    curl -s -X POST "$KIBANA_URL/api/exception_lists/items" \
    -H 'kbn-xsrf: true' \
    -H 'Content-Type: application/json' \
    -H "Authorization: ApiKey $KIBANA_API_KEY" \
    --insecure \
    -d '{
      "list_id": "internal_users",
      "entry_type": "simple",
      "fields": [
        {
          "field": "email.from.address",
          "value": "'"$user"'"
        }
      ]
    }' | jq .
done

echo "Step 4: Adding internal domains to the list."
for domain in "${INTERNAL_DOMAINS[@]}"; do
    curl -s -X POST "$KIBANA_URL/api/exception_lists/items" \
    -H 'kbn-xsrf: true' \
    -H 'Content-Type: application/json' \
    -H "Authorization: ApiKey $KIBANA_API_KEY" \
    --insecure \
    -d '{
      "list_id": "internal_domains",
      "entry_type": "simple",
      "fields": [
        {
          "field": "email.to.domain",
          "value": "'"$domain"'"
        }
      ]
    }' | jq .
done

echo "---------------------------------------------------"
echo "Exception lists and items created successfully."
