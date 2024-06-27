# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import argparse
import glob
import hashlib
import json
import os
import yara
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def check_syntax(rule_file):
    try:
        # Testing if compilation throws a syntax error, don't save the result
        yara.compile(filepath=rule_file)
        return (True, rule_file, None)
    except yara.SyntaxError as e:
        # Return the error message for logging purposes
        return (False, rule_file, str(e))

def compile_yara_rules(rules_dir):
    compiled_dir = os.path.join(rules_dir, "compiled")
    compiled_rules_path = "/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled"
    rule_files = glob.glob(os.path.join(rules_dir, '**/*.yar'), recursive=True)
    files_to_compile = {}
    removed_count = 0
    success_count = 0

    # Use ThreadPoolExecutor to parallelize syntax checks
    with ThreadPoolExecutor() as executor:
        results = executor.map(check_syntax, rule_files)

    # Collect yara files and prepare for batch compilation
    ts = str(datetime.utcnow().isoformat())
    failure_ids = []
    success_ids = []
    for success, rule_file, error_message in results:
        rule_id = os.path.splitext(os.path.basename(rule_file))[0]
        if success:
            files_to_compile[os.path.basename(rule_file)] = rule_file
            success_count += 1
            success_ids.append(rule_id)
        else:
            failure_ids.append(rule_id)
            # Extract just the UUID from the rule file name
            log_entry = {
                "event_module": "soc",
                "event_dataset": "soc.detections",
                "log.level": "error",
                "error_message": error_message,
                "error_analysis": "Syntax Error",
                "detection_type": "YARA",
                "rule_uuid": rule_id,
                "error_type": "runtime_status"
            }
            with open('/opt/sensoroni/logs/detections_runtime-status_yara.log', 'a') as log_file:
                json.dump(log_entry, log_file)
                log_file.write('\n')  # Ensure new entries start on new lines
            os.remove(rule_file)
            removed_count += 1

    # Compile all remaining valid rules into a single file
    compiled_sha256=""
    if files_to_compile:
        compiled_rules = yara.compile(filepaths=files_to_compile)
        compiled_rules.save(compiled_rules_path)
        print(f"All remaining rules compiled and saved into {compiled_rules_path}")
        # Hash file
        with open(compiled_rules_path, 'rb') as hash_file:
            compiled_sha256=hashlib.sha256(hash_file.read()).hexdigest()
    # Remove the rules.compiled if there aren't any files to be compiled
    else:
        if os.path.exists(compiled_rules_path):
            os.remove(compiled_rules_path)

    # Create compilation report
    compilation_report = {
      "timestamp": ts,
      "compiled_sha256": compiled_sha256,
      "failure": failure_ids,
      "success": success_ids
    }

    # Write total
    with open('/opt/so/state/detections_yara_compilation-total.log', 'w+') as report_file:
        json.dump(compilation_report, report_file)

    # Print summary of compilation results
    print(f"Summary: {success_count} rules compiled successfully, {removed_count} rules removed due to errors.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compile YARA rules from the specified directory")
    parser.add_argument("rules_dir", help="Directory containing YARA rules to compile")
    args = parser.parse_args()

compile_yara_rules(args.rules_dir)
