from datetime import datetime
import sys
import getopt
from so_elastic_defend_filters_helper import *
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')

# Define mappings for Target Field, Event Type, Conditions
TARGET_FIELD_MAPPINGS = {
    "Image": "process.executable",
    "ParentImage": "process.parent.executable",
    "CommandLine": "process.command_line",
    "ParentCommandLine": "process.parent.command_line",
    "DestinationHostname": "destination.domain",
    "QueryName": "dns.question.name",
    "DestinationIp": "destination.ip",
    "TargetObject": "registry.path",
    "TargetFilename": "file.path"
}

DATASET_MAPPINGS = {
    "process_create": "endpoint.events.process",
    "network_connection": "endpoint.events.network",
    "file_create": "endpoint.events.file",
    "file_delete": "endpoint.events.file",
    "registry_event": "endpoint.events.registry",
    "dns_query": "endpoint.events.network"
}

CONDITION_MAPPINGS = {
    "is": ("included", "match"),
    "end with": ("included", "wildcard"),
    "begin with": ("included", "wildcard"),
    "contains": ("included", "wildcard")
}

# Extract entries for a rule
def extract_entries(data, event_type):
    entries = []
    filter_data = data.get('filter', {})
    for value in filter_data.values():
        target_field = TARGET_FIELD_MAPPINGS.get(value.get('TargetField', ''))
        condition = value.get('Condition', '')
        pattern = value.get('Pattern', '')

        if condition not in CONDITION_MAPPINGS:
            logging.error(f"Invalid condition: {condition}")

        # Modify the pattern based on the condition
        pattern = modify_pattern(condition, pattern)

        operator, match_type = CONDITION_MAPPINGS[condition]

        entries.append({
            "field": target_field,
            "operator": operator,
            "type": match_type,
            "value": pattern
        })

    # Add the event.dataset entry from DATASET_MAPPINGS
    dataset_value = DATASET_MAPPINGS.get(event_type, '')
    if dataset_value:
        entries.append({
            "field": "event.dataset",
            "operator": "included",
            "type": "match",
            "value": dataset_value
        })
    else:
        logging.error(f"No dataset mapping found for event_type: {event_type}")

    return entries

# Build the JSON
def build_json_entry(entries, guid, event_type, context):
    return {
        "comments": [],
        "entries": entries,
        "item_id": guid,
        "name": f"SO - {event_type} - {guid}",
        "description": f"{context}\n\n  <<- Note: This filter is managed by Security Onion. ->>",
        "namespace_type": "agnostic",
        "tags": ["policy:all"],
        "type": "simple",
        "os_types": ["windows"],
        "entries": entries
    }

# Check to see if the rule is disabled
# If it is, make sure it is not active
def disable_check(guid, disabled_rules, username, password):
    if guid in disabled_rules:
        logging.info(f"Rule {guid} is in the disabled rules list, confirming that is is actually disabled...")
        existing_rule = api_request("GET", guid, username, password)

        if existing_rule:
            if api_request("DELETE", guid, username, password):
                logging.info(f"Successfully deleted rule {guid}")
                return True, "deleted"
            else:
                logging.error(f"Error deleting rule {guid}.")
                return True, "Error deleting"
        return True, "NOP"
    return False, None

def modify_pattern(condition, pattern):
    """
    Modify the pattern based on the condition.
    - 'end with': Add '*' to the beginning of the pattern.
    - 'begin with': Add '*' to the end of the pattern.
    - 'contains': Add '*' to both the beginning and end of the pattern.
    """
    if isinstance(pattern, list):
        # Apply modification to each pattern in the list if it's a list of patterns
        return [modify_pattern(condition, p) for p in pattern]
    
    if condition == "end with":
        return f"*{pattern}"
    elif condition == "begin with":
        return f"{pattern}*"
    elif condition == "contains":
        return f"*{pattern}*"
    return pattern


def process_rule_update_or_create(guid, json_entry, username, password):
    existing_rule = api_request("GET", guid, username, password)

    if existing_rule:
        existing_rule_data = extract_relevant_fields(existing_rule)
        new_rule_data = extract_relevant_fields(json_entry)
        if generate_hash(existing_rule_data) != generate_hash(new_rule_data):
            logging.info(f"Updating rule {guid}")
            json_entry.pop("list_id", None)
            api_request("PUT", guid, username, password, json_data=json_entry)
            return "updated"
        logging.info(f"Rule {guid} is up to date.")
        return "no_change"
    else:
        logging.info(f"Creating new rule {guid}")
        json_entry["list_id"] = "endpoint_event_filters"
        api_request("POST", guid, username, password, json_data=json_entry)
        return "new"

# Main function for processing rules
def process_rules(yaml_files, disabled_rules, username, password):
    stats = {"rule_count": 0, "new": 0, "updated": 0, "no_change": 0, "disabled": 0, "deleted": 0}
    for data in yaml_files:
        logging.info(f"Processing rule: {data.get('id', '')}")
        event_type = data.get('event_type', '')
        guid = data.get('id', '')
        dataset = DATASET_MAPPINGS.get(event_type, '')
        context = data.get('description', '')

        rule_deleted, state = disable_check(guid, disabled_rules, username, password)
        if rule_deleted:
            stats["disabled"] += 1
            if state == "deleted":
                stats["deleted"] += 1
            continue

        # Extract entries and build JSON
        entries = extract_entries(data, event_type)
        json_entry = build_json_entry(entries, guid, event_type, context)

        # Process rule creation or update
        status = process_rule_update_or_create(guid, json_entry, username, password)

        stats[status] += 1
        stats["rule_count"] += 1
    return stats

def parse_args(argv):
    try:
        opts, args = getopt.getopt(argv, "i:d:c:f:", ["input=", "disabled=", "credentials=", "flags_file="])
    except getopt.GetoptError:
        print("Usage: python so-elastic-defend-manage-filters.py -c <credentials_file> -d <disabled_file> -i <folder_of_yaml_files> [-f <flags_file>]")
        sys.exit(2)
    return opts

def load_flags(file_path):
    with open(file_path, 'r') as flags_file:
        return flags_file.read().splitlines()

def validate_inputs(credentials_file, disabled_file, yaml_directories):
    if not credentials_file or not disabled_file or not yaml_directories:
        print("Usage: python so-elastic-defend-manage-filters.py -c <credentials_file> -d <disabled_file> -i <folder_of_yaml_files> [-f <flags_file>]")
        sys.exit(2)

def main(argv):
    credentials_file = ""
    disabled_file = ""
    yaml_directories = []

    opts = parse_args(argv)

    for opt, arg in opts:
        if opt in ("-c", "--credentials"):
            credentials_file = arg
        elif opt in ("-d", "--disabled"):
            disabled_file = arg
        elif opt in ("-i", "--input"):
            yaml_directories.append(arg)
        elif opt in ("-f", "--flags_file"):
            flags = load_flags(arg)
            return main(argv + flags)

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"\n{timestamp}")

    validate_inputs(credentials_file, disabled_file, yaml_directories)

    credentials = load_credentials(credentials_file)
    if not credentials:
        raise Exception("Failed to load credentials")

    username, password = extract_auth_details(credentials)
    if not username or not password:
        raise Exception("Invalid credentials format")

    custom_rules_input = '/opt/so/conf/elastic-fleet/defend-exclusions/rulesets/custom-filters-raw'
    custom_rules_output = '/opt/so/conf/elastic-fleet/defend-exclusions/rulesets/custom-filters'
    prepare_custom_rules(custom_rules_input, custom_rules_output)
    disabled_rules = load_disabled(disabled_file)

    total_stats = {"rule_count": 0, "new": 0, "updated": 0, "no_change": 0, "disabled": 0, "deleted": 0}

    for yaml_dir in yaml_directories:
        yaml_files = load_yaml_files(yaml_dir)
        stats = process_rules(yaml_files, disabled_rules, username, password)

        for key in total_stats:
            total_stats[key] += stats[key]

    logging.info(f"\nProcessing Summary")
    logging.info(f" - Total processed rules: {total_stats['rule_count']}")
    logging.info(f" - New rules: {total_stats['new']}")
    logging.info(f" - Updated rules: {total_stats['updated']}")
    logging.info(f" - Disabled rules: {total_stats['deleted']}")
    logging.info(f" - Rules with no changes: {total_stats['no_change']}")
    logging.info(f"Rule status Summary")
    logging.info(f" - Active rules: {total_stats['rule_count'] - total_stats['disabled']}")
    logging.info(f" - Disabled rules: {total_stats['disabled']}")
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"Execution completed at: {timestamp}")


if __name__ == "__main__":
    main(sys.argv[1:])
