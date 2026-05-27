import os
import yaml
import argparse
from opensearchpy import OpenSearch, NotFoundError, ConflictError
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_existing_rule_by_title(client, title):
    """
    Searches for an existing rule with a matching title to avoid duplicates.

    Args:
        client (OpenSearch): The OpenSearch client object.
        title (str): The title of the rule to search for.

    Returns:
        bool: True if a rule with the title exists, False otherwise.
    """
    try:
        query = {
            "query": {
                "term": {
                    "rule.title.keyword": title
                }
            }
        }
        # Assuming rules are stored in an index like .opensearch-security-analytics-config-rules
        response = client.search(index='_plugins/_security_analytics/rules', body=query)

        if response['hits']['total']['value'] > 0:
            return True
        return False
    except NotFoundError:
        # Index doesn't exist yet, so no rules can exist.
        return False
    except Exception as e:
        logging.error(f"Error checking for existing rule: {str(e)}")
        return False

def main():
    """
    Main function to parse arguments and import YAML files into OpenSearch.
    """
    parser = argparse.ArgumentParser(description="Recursively import Sigma .yaml files into OpenSearch Security Analytics Rules API.")
    parser.add_argument('--host', default='localhost', help="OpenSearch host (default: localhost)")
    parser.add_argument('--port', default=9200, type=int, help="OpenSearch port (default: 9200)")
    parser.add_argument('--scheme', default='http', help="Connection scheme (http or https, default: http)")
    parser.add_argument('--username', default=None, help="OpenSearch username (optional)")
    parser.add_argument('--password', default=None, help="OpenSearch password (optional)")
    parser.add_argument('--verify_certs', action='store_true', help="Verify SSL certificates (default: False)")

    args = parser.parse_args()

    # Prepare OpenSearch client configuration
    hosts = [{'host': args.host, 'port': args.port}]
    auth = (args.username, args.password) if args.username and args.password else None

    client = OpenSearch(
        hosts=hosts,
        http_auth=auth,
        use_ssl=(args.scheme == 'https'),
        verify_certs=args.verify_certs,
        ssl_show_warn=not args.verify_certs
    )

    # Recursively walk the current directory
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.yaml'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as f:
                        data = yaml.safe_load(f)

                    # Validate required fields
                    if 'logsource' not in data or 'product' not in data['logsource']:
                        raise ValueError("Missing 'logsource.product' in the Sigma rule.")
                    if 'title' not in data:
                        raise ValueError("Missing 'title' in the Sigma rule, which is required for duplicate checking.")

                    category = data['logsource']['product']
                    title = data['title']

                    # Check for duplicate rule before uploading
                    if get_existing_rule_by_title(client, title):
                        logging.warning(f"Rule with title '{title}' from {file_path} already exists. Skipping.")
                        continue

                    # Create the rule via API
                    response = client.transport.perform_request(
                        'POST',
                        f'/_plugins/_security_analytics/rules?category={category}',
                        body=data
                    )
                    logging.info(f"Successfully created rule from {file_path} with ID {response['_id']}")

                except FileNotFoundError:
                    logging.error(f"Error processing {file_path}: File not found.")
                except yaml.YAMLError as e:
                    logging.error(f"Error parsing YAML file {file_path}: {str(e)}")
                except ValueError as e:
                    logging.error(f"Validation error in {file_path}: {str(e)}")
                except ConflictError:
                    logging.warning(f"Rule conflict detected for {file_path}. A rule with this name or ID may already exist.")
                except Exception as e:
                    logging.error(f"Unexpected error processing {file_path}: {str(e)}")

if __name__ == "__main__":
    main()
