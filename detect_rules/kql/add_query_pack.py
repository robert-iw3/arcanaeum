import os
import logging
import subprocess
import sys
from typing import Dict, Any, Optional

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient

# Configure logging for better visibility and debugging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def get_config() -> Dict[str, Optional[str]]:
    """
    Retrieves and validates configuration from environment variables.
    """
    config = {
        "subscription_id": os.environ.get("AZURE_SUBSCRIPTION_ID"),
        "resource_group_name": os.environ.get("RESOURCE_GROUP_NAME"),
        "query_pack_name": os.environ.get("QUERY_PACK_NAME"),
        "location": os.environ.get("AZURE_LOCATION"),
    }

    for key, value in config.items():
        if not value:
            logging.critical(f"Missing environment variable: {key.upper()}")
            raise ValueError(f"Missing environment variable: {key.upper()}")

    return config

def get_monitor_client(subscription_id: str) -> MonitorManagementClient:
    """
    Initializes and returns an authenticated MonitorManagementClient.
    """
    try:
        credential = DefaultAzureCredential()
        client = MonitorManagementClient(credential, subscription_id)
        logging.info("Authentication with Azure successful.")
        return client
    except Exception as ex:
        logging.critical(f"Failed to authenticate with Azure: {ex}")
        raise RuntimeError("Authentication failed.") from ex

def create_query_pack(
    monitor_client: MonitorManagementClient,
    resource_group: str,
    query_pack: str,
    location: str
) -> Optional[Any]:
    """
    Creates a Log Analytics Query Pack in the specified resource group and location.
    Handles existence checks to be idempotent.
    """
    try:
        # The create_or_update method is idempotent, so we can directly call it.
        # It's more efficient than a separate get() check.
        logging.info(f"Creating or updating query pack '{query_pack}' in '{resource_group}'...")
        query_pack_resource = monitor_client.log_analytics_query_packs.begin_create_or_update(
            resource_group,
            query_pack,
            {"location": location}
        ).result()
        logging.info(f"Successfully created or updated query pack: {query_pack_resource.id}")
        return query_pack_resource
    except HttpResponseError as ex:
        logging.error(f"Failed to create query pack due to an HTTP error: {ex.message}")
    except Exception as ex:
        logging.error(f"An unexpected error occurred while creating the query pack: {ex}")
    return None

def run_next_script(script_name: str, args: Optional[list] = None):
    """
    Executes another Python script using subprocess.
    """
    script_path = os.path.join(os.getcwd(), script_name)
    if not os.path.exists(script_path):
        logging.error(f"Cannot find script: {script_path}")
        return False

    command = [sys.executable, script_path]
    if args:
        command.extend(args)

    logging.info(f"Calling subprocess to execute: {' '.join(command)}")
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        logging.info(f"Script '{script_name}' completed successfully.")
        logging.info(f"Script '{script_name}' STDOUT:\n{result.stdout}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Script '{script_name}' failed with exit code {e.returncode}.")
        logging.error(f"Script '{script_name}' STDERR:\n{e.stderr}")
    except FileNotFoundError:
        logging.error(f"The Python executable was not found. Please check your environment.")
    except Exception as ex:
        logging.error(f"An unexpected error occurred while running the script: {ex}")
    return False

def main():
    """
    Main function to run the script.
    """
    try:
        config = get_config()
        monitor_client = get_monitor_client(config["subscription_id"])

        new_query_pack = create_query_pack(
            monitor_client,
            config["resource_group_name"],
            config["query_pack_name"],
            config["location"]
        )

        if new_query_pack:
            logging.info("\nQuery pack creation process complete. Starting next step.")

            # --- Call the next script ---
            # You can pass additional arguments if needed by modifying the run_next_script call.
            # Example: run_next_script("import_kql_sentinel.py", args=["--pack-id", new_query_pack.id])
            success = run_next_script("import_kql_sentinel.py")
            if success:
                logging.info("import_kql_sentinel.py executed successfully.")
            else:
                logging.error("Failed to execute import_kql_sentinel.py.")

    except (ValueError, RuntimeError):
        logging.critical("Script aborted due to configuration or authentication issues.")
    except Exception as ex:
        logging.critical(f"An unhandled error occurred: {ex}")

if __name__ == "__main__":
    main()

