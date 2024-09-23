
import hashlib
import os
import json
import yaml
import requests
from requests.auth import HTTPBasicAuth
import shutil

# Extract 'entries', 'description' and 'os_types' fields
def extract_relevant_fields(filter):
    return {
        'entries': filter.get('entries', []),
        'description': filter.get('description', '')
    }

# Sort for consistency, so that a hash can be generated
def sorted_data(value):
    if isinstance(value, dict):
        # Recursively sort the dictionary by key
        return {k: sorted_data(v) for k, v in sorted(value.items())}
    elif isinstance(value, list):
        # Sort lists; for dictionaries, sort by a specific key
        return sorted(value, key=lambda x: tuple(sorted(x.items())) if isinstance(x, dict) else x)
    return value

# Generate a hash based on sorted relevant fields
def generate_hash(data):
    sorted_data_string = json.dumps(sorted_data(data), sort_keys=True)
    return hashlib.sha256(sorted_data_string.encode('utf-8')).hexdigest()

# Load Elasticsearch credentials from the config file
def load_credentials(config_path):
    with open(config_path, 'r') as file:
        for line in file:
            if line.startswith("user"):
                credentials = line.split('=', 1)[1].strip().strip('"')
                return credentials
    return None

# Extract username and password from credentials
def extract_auth_details(credentials):
    if ':' in credentials:
        return credentials.split(':', 1)
    return None, None

# Generalized API request function
def api_request(method, guid, username, password, json_data=None):
    headers = {
        'kbn-xsrf': 'true',
        'Content-Type': 'application/json'
    }
    auth = HTTPBasicAuth(username, password)

    if method == "POST":
        url = "http://localhost:5601/api/exception_lists/items?namespace_type=agnostic"
    else:
        url = f"http://localhost:5601/api/exception_lists/items?item_id={guid}&namespace_type=agnostic"

    response = requests.request(method, url, headers=headers, auth=auth, json=json_data)
    
    if response.status_code in [200, 201]:
        return response.json() if response.content else True
    elif response.status_code == 404 and method == "GET":
        return None
    else:
        print(f"Error with {method} request: {response.status_code} - {response.text}")
        return False
    

# Load YAML data for GUIDs to skip
def load_disabled(disabled_file_path):
    if os.path.exists(disabled_file_path):
        with open(disabled_file_path, 'r') as file:
            return yaml.safe_load(file) or {}
    return {}

def load_yaml_files(*dirs):
    yaml_files = []
    
    for dir_path in dirs:
        if os.path.isdir(dir_path):
            # Recurse through the directory and subdirectories
            for root, dirs, files in os.walk(dir_path):
                for file_name in files:
                    if file_name.endswith(".yaml"):
                        full_path = os.path.join(root, file_name)
                        with open(full_path, 'r') as f:
                            try:
                                yaml_content = yaml.safe_load(f)
                                yaml_files.append(yaml_content)
                            except yaml.YAMLError as e:
                                print(f"Error loading {full_path}: {e}")
        else:
            print(f"Invalid directory: {dir_path}")
    
    return yaml_files

def prepare_custom_rules(input_file, output_dir):
    # Clear the output directory first
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # Load the YAML file
        with open(input_file, 'r') as f:
            docs = yaml.safe_load_all(f)
            
            for doc in docs:
                if 'id' not in doc:
                    print(f"Skipping rule, no 'id' found: {doc}")
                    continue
                if doc.get('title') in ["Template 1", "Template 2"]:
                    print(f"Skipping template rule with title: {doc['title']}")
                    continue
                # Create a filename using the 'id' field
                file_name = os.path.join(output_dir, f"{doc['id']}.yaml")
                
                # Write the individual YAML file
                with open(file_name, 'w') as output_file:
                    yaml.dump(doc, output_file, default_flow_style=False)
                print(f"Created file: {file_name}")
    
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
    except Exception as e:
        print(f"Error processing file: {e}")