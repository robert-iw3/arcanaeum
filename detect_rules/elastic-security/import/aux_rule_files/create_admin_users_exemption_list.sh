#!/bin/bash

# --- Configuration ---
KIBANA_URL="https://your_kibana_url:5601"
# API key with saved_object_management privileges (e.g., KIBANA_API_KEY from previous script)
KIBANA_API_KEY="<your_encoded_api_key>"
# List of administrative users to be added to the exception list
ADMIN_USERS=(
    "svc_account_1"
    "svc_account_2"
    "ad_admin"
)

# --- Script starts here ---

# Function to check if a command was successful
check_success() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed."
        exit 1
    fi
}

echo "Step 1: Creating the shared exception list container."

# Create the exception list container
RESPONSE=$(curl -s -X POST "$KIBANA_URL/api/exception_lists" \
-H 'kbn-xsrf: true' \
-H 'Content-Type: application/json' \
-H "Authorization: ApiKey $KIBANA_API_KEY" \
--insecure \
-d '{
  "id": "admin_users",
  "name": "Administrative Users",
  "namespace_type": "single",
  "description": "Exempts known administrative users from security detection rules."
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

echo "Step 2: Adding administrative users to the exception list."

# Loop through the list of users and add them as items
for user in "${ADMIN_USERS[@]}"; do
    echo "Adding user: $user"
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
          "field": "winlog.event_data.SubjectUserName",
          "value": "'"$user"'"
        }
      ]
    }')
    check_success "Adding list item for $user"
    echo "$ITEM_RESPONSE" | jq .
done

echo "---------------------------------------------------"
echo "Exception list and items created successfully."
