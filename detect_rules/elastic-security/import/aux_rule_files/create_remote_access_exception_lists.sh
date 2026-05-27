#!/bin/bash

# --- Configuration ---
KIBANA_URL="https://your_kibana_url:5601"
KIBANA_API_KEY="<your_encoded_api_key>"
AUTHORIZED_USERS=(
    "admin_user1"
    "admin_user2"
)
AUTHORIZED_PARENTS=(
    "legitimate_parent1.exe"
    "legitimate_parent2.exe"
)

# --- Script starts here ---

# Function to check if a command was successful
check_success() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed."
        exit 1
    fi
}

echo "Step 1: Creating the exception list for authorized remote users."
curl -s -X POST "$KIBANA_URL/api/exception_lists" \
-H 'kbn-xsrf: true' \
-H 'Content-Type: application/json' \
-H "Authorization: ApiKey $KIBANA_API_KEY" \
--insecure \
-d '{
  "id": "authorized_remote_users",
  "name": "Authorized Remote Access Users",
  "namespace_type": "single",
  "description": "Exempts authorized users from remote access tool detection."
}' | jq .
check_success "Authorized users list creation"

echo "Step 2: Creating the exception list for authorized remote parents."
curl -s -X POST "$KIBANA_URL/api/exception_lists" \
-H 'kbn-xsrf: true' \
-H 'Content-Type: application/json' \
-H "Authorization: ApiKey $KIBANA_API_KEY" \
--insecure \
-d '{
  "id": "authorized_remote_parents",
  "name": "Authorized Remote Access Parents",
  "namespace_type": "single",
  "description": "Exempts authorized parent processes from remote access tool detection."
}' | jq .
check_success "Authorized parents list creation"

echo "Step 3: Adding authorized users to the list."
for user in "${AUTHORIZED_USERS[@]}"; do
    curl -s -X POST "$KIBANA_URL/api/exception_lists/items" \
    -H 'kbn-xsrf: true' \
    -H 'Content-Type: application/json' \
    -H "Authorization: ApiKey $KIBANA_API_KEY" \
    --insecure \
    -d '{
      "list_id": "authorized_remote_users",
      "entry_type": "simple",
      "fields": [
        {
          "field": "user.name",
          "value": "'"$user"'"
        }
      ]
    }' | jq .
done

echo "Step 4: Adding authorized parent processes to the list."
for parent in "${AUTHORIZED_PARENTS[@]}"; do
    curl -s -X POST "$KIBANA_URL/api/exception_lists/items" \
    -H 'kbn-xsrf: true' \
    -H 'Content-Type: application/json' \
    -H "Authorization: ApiKey $KIBANA_API_KEY" \
    --insecure \
    -d '{
      "list_id": "authorized_remote_parents",
      "entry_type": "simple",
      "fields": [
        {
          "field": "process.parent.name",
          "value": "'"$parent"'"
        }
      ]
    }' | jq .
done

echo "---------------------------------------------------"
echo "Exception lists and items created successfully."
