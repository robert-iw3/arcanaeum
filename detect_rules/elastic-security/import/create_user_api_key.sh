#!/bin/bash

# --- Configuration ---
KIBANA_URL="${KIBANA_URL}"
# Superuser credentials for creating the new user and role
SUPERUSER_USERNAME="elastic"
SUPERUSER_PASSWORD="${SUPERUSER_PASSWORD}"
# Credentials for the new dedicated user
IMPORT_USERNAME="${IMPORT_USERNAME:-saved_object_importer_user}"
IMPORT_PASSWORD="${IMPORT_PASSWORD}"
# Name for the new role and API key
ROLE_NAME="${ROLE_NAME:-saved_object_importer_role}"
API_KEY_NAME="${API_KEY_NAME:-saved_object_importer_key}"

# --- Script starts here ---

# Function to check if a command was successful
check_success() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed."
        exit 1
    fi
}

echo "Step 1: Creating the '$ROLE_NAME' role with saved_object_management privileges."

# Create the role
curl -XPOST "$KIBANA_URL/api/security/roles/$ROLE_NAME" \
-H 'kbn-xsrf: true' \
-H 'Content-Type: application/json' \
-u "$SUPERUSER_USERNAME:$SUPERUSER_PASSWORD" \
--insecure \
-d '{
  "kibana": [
    {
      "base": [
        "all"
      ],
      "spaces": [
        "*"
      ],
      "privileges": [
        "saved_object_management"
      ]
    }
  ]
}'
check_success "Role creation"

echo "Role '$ROLE_NAME' created successfully."
echo "---------------------------------------------------"

echo "Step 2: Creating the '$IMPORT_USERNAME' user and assigning the '$ROLE_NAME' role."

# Create the user
curl -XPOST "$KIBANA_URL/api/security/users/$IMPORT_USERNAME" \
-H 'kbn-xsrf: true' \
-H 'Content-Type: application/json' \
-u "$SUPERUSER_USERNAME:$SUPERUSER_PASSWORD" \
--insecure \
-d "{
  \"password\" : \"$IMPORT_PASSWORD\",
  \"roles\" : [ \"$ROLE_NAME\" ]
}"
check_success "User creation"

echo "User '$IMPORT_USERNAME' created successfully."
echo "---------------------------------------------------"

echo "Step 3: Creating the API key for '$IMPORT_USERNAME'."

# Create the API key and capture the response
RESPONSE=$(curl -s -X POST "$KIBANA_URL/api/security/api_key" \
-H 'kbn-xsrf: true' \
-H 'Content-Type: application/json' \
-u "$IMPORT_USERNAME:$IMPORT_PASSWORD" \
--insecure \
-d "{ \"name\": \"$API_KEY_NAME\" }")
check_success "API key creation"

# Extract the encoded API key using jq
ENCODED_API_KEY=$(echo "$RESPONSE" | jq -r '.encoded')

if [ "$ENCODED_API_KEY" == "null" ] || [ -z "$ENCODED_API_KEY" ]; then
    echo "Error: Failed to extract encoded API key from response."
    echo "Full response: $RESPONSE"
    exit 1
fi

echo "API key created successfully."
echo "---------------------------------------------------"
echo "Your new encoded API key is:"
echo "$ENCODED_API_KEY"
echo "---------------------------------------------------"
echo "Use this key in your Authorization header like this: Authorization: ApiKey $ENCODED_API_KEY"

export KIBANA_API_KEY="$ENCODED_API_KEY"