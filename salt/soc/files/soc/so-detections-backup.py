# Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# This script queries Elasticsearch for Custom Detections and all Overrides,
# and git commits them to disk at $OUTPUT_DIR

import os
import subprocess
import json
import requests
from requests.auth import HTTPBasicAuth
import urllib3
from datetime import datetime

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
ES_URL = "https://localhost:9200/so-detection/_search"
QUERY_DETECTIONS = '{"query": {"bool": {"must": [{"match_all": {}}, {"term": {"so_detection.ruleset": "__custom__"}}]}},"size": 10000}'
QUERY_OVERRIDES = '{"query": {"bool": {"must": [{"exists": {"field": "so_detection.overrides"}}]}},"size": 10000}'
OUTPUT_DIR = "/nsm/backup/detections/repo"
AUTH_FILE = "/opt/so/conf/elasticsearch/curl.config"

def get_auth_credentials(auth_file):
    with open(auth_file, 'r') as file:
        for line in file:
            if line.startswith('user ='):
                return line.split('=', 1)[1].strip().replace('"', '')

def query_elasticsearch(query, auth):
    headers = {"Content-Type": "application/json"}
    response = requests.get(ES_URL, headers=headers, data=query, auth=auth, verify=False)
    response.raise_for_status()
    return response.json()

def save_content(hit, base_folder, subfolder="", extension="txt"):
    so_detection = hit["_source"]["so_detection"]
    public_id = so_detection["publicId"]
    content = so_detection["content"]
    file_dir = os.path.join(base_folder, subfolder)
    os.makedirs(file_dir, exist_ok=True)
    file_path = os.path.join(file_dir, f"{public_id}.{extension}")
    with open(file_path, "w") as f:
        f.write(content)
    return file_path

def save_overrides(hit):
    so_detection = hit["_source"]["so_detection"]
    public_id = so_detection["publicId"]
    overrides = so_detection["overrides"]
    language = so_detection["language"]
    folder = os.path.join(OUTPUT_DIR, language, "overrides")
    os.makedirs(folder, exist_ok=True)
    extension = "yaml" if language == "sigma" else "txt"
    file_path = os.path.join(folder, f"{public_id}.{extension}")
    with open(file_path, "w") as f:
        f.write('\n'.join(json.dumps(override) for override in overrides) if isinstance(overrides, list) else overrides)
    return file_path

def ensure_git_repo():
    if not os.path.isdir(os.path.join(OUTPUT_DIR, '.git')):
        subprocess.run(["git", "config", "--global", "init.defaultBranch", "main"], check=True)
        subprocess.run(["git", "-C", OUTPUT_DIR, "init"], check=True)
        subprocess.run(["git", "-C", OUTPUT_DIR, "remote", "add", "origin", "default"], check=True)

def commit_changes():
    ensure_git_repo()
    subprocess.run(["git", "-C", OUTPUT_DIR, "config", "user.email", "securityonion@local.invalid"], check=True)
    subprocess.run(["git", "-C", OUTPUT_DIR, "config", "user.name", "securityonion"], check=True)
    subprocess.run(["git", "-C", OUTPUT_DIR, "add", "."], check=True)
    status_result = subprocess.run(["git", "-C", OUTPUT_DIR, "status"], capture_output=True, text=True)
    print(status_result.stdout)
    commit_result = subprocess.run(["git", "-C", OUTPUT_DIR, "commit", "-m", "Update detections and overrides"], check=False, capture_output=True)
    if commit_result.returncode == 1:
        print("No changes to commit.")
    elif commit_result.returncode == 0:
        print("Changes committed successfully.")
    else:
        commit_result.check_returncode()

def main():
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"Backing up Custom Detections and all Overrides to {OUTPUT_DIR} - {timestamp}\n")
        
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        auth_credentials = get_auth_credentials(AUTH_FILE)
        username, password = auth_credentials.split(':', 1)
        auth = HTTPBasicAuth(username, password)
        
        # Query and save custom detections
        detections = query_elasticsearch(QUERY_DETECTIONS, auth)["hits"]["hits"]
        for hit in detections:
            save_content(hit, OUTPUT_DIR, hit["_source"]["so_detection"]["language"], "yaml" if hit["_source"]["so_detection"]["language"] == "sigma" else "txt")
        
        # Query and save overrides
        overrides = query_elasticsearch(QUERY_OVERRIDES, auth)["hits"]["hits"]
        for hit in overrides:
            save_overrides(hit)
        
        commit_changes()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"Backup Completed - {timestamp}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()