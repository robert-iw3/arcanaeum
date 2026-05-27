import os
import glob
import json
from azure.identity import DefaultAzureCredential
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError
import uuid
import sys
import re

# --- Configuration ---
SUBSCRIPTION_ID = os.getenv('SUBSCRIPTION_ID')
RESOURCE_GROUP_NAME = os.getenv('RESOURCE_GROUP_NAME')
WORKSPACE_NAME = os.getenv('WORKSPACE_NAME')
LOCATION = os.getenv('AZURE_LOCATION', 'eastus2') # Default to a region, or get from environment
IMPORT_DIRECTORY = os.path.join(os.getcwd(), "import")
# Define the Saved Search category for imported queries.
SAVED_SEARCH_CATEGORY = "Hunting Queries"
# Version for saved search. V2 indicates a KQL query.
SAVED_SEARCH_VERSION = 2

def get_clients():
    """Authenticates and returns Azure clients for Log Analytics and Resource Management."""
    try:
        credential = DefaultAzureCredential()
        log_analytics_client = LogAnalyticsManagementClient(credential, SUBSCRIPTION_ID)
        resource_client = ResourceManagementClient(credential, SUBSCRIPTION_ID)
        print("Authenticated successfully to Azure.")
        return log_analytics_client, resource_client
    except Exception as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        return None, None

def check_or_create_workspace(log_analytics_client, resource_client):
    """
    Checks for the existence of the Log Analytics workspace and creates it if it doesn't exist.
    """
    print(f"Checking for Log Analytics workspace '{WORKSPACE_NAME}' in resource group '{RESOURCE_GROUP_NAME}'...")
    try:
        log_analytics_client.workspaces.get(RESOURCE_GROUP_NAME, WORKSPACE_NAME)
        print("Workspace found.")
    except HttpResponseError as e:
        if e.response.status_code == 404:
            print("Workspace not found. Creating...")

            # First, check or create the resource group
            print(f"Checking for resource group '{RESOURCE_GROUP_NAME}'...")
            if not resource_client.resource_groups.check_existence(RESOURCE_GROUP_NAME):
                print(f"Resource group '{RESOURCE_GROUP_NAME}' not found. Creating...")
                resource_client.resource_groups.create_or_update(RESOURCE_GROUP_NAME, {'location': LOCATION})

            # Create the workspace
            workspace_info = {
                'location': LOCATION,
                'sku': {'name': 'PerGB2018'}
            }
            try:
                # The Log Analytics client uses a begin_create_or_update method for long-running operations.
                creation_poller = log_analytics_client.workspaces.begin_create_or_update(RESOURCE_GROUP_NAME, WORKSPACE_NAME, workspace_info)
                creation_poller.result()  # Wait for the creation to finish
                print("Workspace created successfully.")
            except HttpResponseError as create_e:
                print(f"Failed to create workspace: {create_e}", file=sys.stderr)
                return False
        else:
            print(f"Error checking workspace: {e}", file=sys.stderr)
            return False
    return True

def import_saved_searches():
    """
    Recursively finds all .json files in the specified directory and imports them as
    Saved Searches into the Microsoft Sentinel Log Analytics workspace.
    """
    log_analytics_client, resource_client = get_clients()
    if not log_analytics_client or not resource_client:
        return

    # Create the workspace if it doesn't exist
    if not check_or_create_workspace(log_analytics_client, resource_client):
        return

    # Find all .json files recursively in the 'import' directory
    json_files = glob.iglob(os.path.join(IMPORT_DIRECTORY, '**/*.json'), recursive=True)

    found_files = list(json_files)
    if not found_files:
        print(f"No .json files found in '{IMPORT_DIRECTORY}'. Exiting.")
        return

    for json_file_path in found_files:
        try:
            print(f"Processing: {json_file_path}")

            # Read the JSON payload from the file
            with open(json_file_path, 'r', encoding='utf-8') as file:
                saved_search_payload = json.load(file)

            # The API expects properties directly, so extract that part
            properties = saved_search_payload['properties']

            # Overwrite the category with the specified one
            properties['category'] = SAVED_SEARCH_CATEGORY
            properties['version'] = SAVED_SEARCH_VERSION

            # The Saved Search ID is required and should be unique.
            # We'll use the display name, sanitized for the ID format.
            display_name = properties['displayName']
            saved_search_id = re.sub(r'[^a-zA-Z0-9]', '', display_name.lower())[:60]
            if not saved_search_id:
                saved_search_id = f"savedsearch-{str(uuid.uuid4())[:8]}"

            # Use the Log Analytics Management Client to create or update the saved search
            log_analytics_client.saved_searches.create_or_update(
                resource_group_name=RESOURCE_GROUP_NAME,
                workspace_name=WORKSPACE_NAME,
                saved_search_id=saved_search_id,
                parameters=properties
            )
            print(f"Successfully created/updated Saved Search '{display_name}' in category '{SAVED_SEARCH_CATEGORY}'.")

        except FileNotFoundError:
            print(f"Error: JSON file not found at {json_file_path}", file=sys.stderr)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in file {json_file_path}", file=sys.stderr)
        except HttpResponseError as e:
            print(f"API error creating Saved Search for {json_file_path}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"An unexpected error occurred for {json_file_path}: {e}", file=sys.stderr)

if __name__ == "__main__":
    if not all([SUBSCRIPTION_ID, RESOURCE_GROUP_NAME, WORKSPACE_NAME]):
        print("Please set the SUBSCRIPTION_ID, RESOURCE_GROUP_NAME, and WORKSPACE_NAME environment variables.", file=sys.stderr)
    else:
        import_saved_searches()
