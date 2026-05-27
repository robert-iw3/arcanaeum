#!/bin/bash

# --- Configuration ---
KIBANA_URL="https://your_kibana_url:5601"
KIBANA_API_KEY="<your_encoded_api_key>"
ADMIN_ROLES=(
    "arn:aws:iam::123456789012:role/trusted-admin-role"
    "arn:aws:iam::123456789012:role/devops-admin-role"
)
TRUSTED_IPS=(
    "10.0.0.0/8"
)

# --- Script starts here ---

# Function to check if a command was successful
check_success() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed."
        exit 1
    fi
}

echo "Step 1: Creating the shared exception list container for admin roles."
RESPONSE=$(curl -s -X POST "$KIBANA_URL/api/exception_lists" \
-H 'kbn-xsrf: true' \
-H 'Content-Type: application/json' \
-H "Authorization: ApiKey $KIBANA_API_KEY" \
--insecure \
-d '{
  "id": "known_ssm_users",
  "name": "Known SSM Users/IPs",
  "namespace_type": "single",
  "description": "Exempts known administrative roles and trusted IPs from SSM session detection."
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

echo "Step 2: Adding admin role ARNs and trusted IPs to the exception list."
for role_arn in "${ADMIN_ROLES[@]}"; do
    echo "Adding ARN: $role_arn"
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
          "field": "aws.cloudtrail.userIdentity.arn",
          "value": "'"$role_arn"'"
        }
      ]
    }' | jq .
done

for ip in "${TRUSTED_IPS[@]}"; do
    echo "Adding IP: $ip"
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
          "field": "source.ip",
          "value": "'"$ip"'"
        }
      ]
    }' | jq .
done
echo "---------------------------------------------------"
echo "Exception list and items created successfully."
