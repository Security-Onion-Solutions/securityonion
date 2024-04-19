# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import os
import yara
import glob
import json
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
    compiled_rules_path = os.path.join(compiled_dir, "rules.compiled")
    rule_files = glob.glob(os.path.join(rules_dir, '**/*.yar'), recursive=True)
    files_to_compile = {}
    removed_count = 0
    success_count = 0
    
    # Use ThreadPoolExecutor to parallelize syntax checks
    with ThreadPoolExecutor() as executor:
        results = executor.map(check_syntax, rule_files)
    
    # Collect yara files and prepare for batch compilation
    for success, rule_file, error_message in results:
        if success:
            files_to_compile[os.path.basename(rule_file)] = rule_file
            success_count += 1
        else:
            # Extract just the UUID from the rule file name
            rule_id = os.path.splitext(os.path.basename(rule_file))[0]
            log_entry = {
                "event.module": "soc",
                "event.dataset": "soc.detections",
                "log.level": "error",
                "error.message": error_message,
                "error.analysis": "syntax error",
                "detection_type": "yara",
                "rule.uuid": rule_id,
                "error.type": "runtime_status"
            }
            with open('/opt/sensoroni/logs/detections_runtime-status_yara.log', 'a') as log_file:
                json.dump(log_entry, log_file)
                log_file.write('\n')  # Ensure new entries start on new lines
            os.remove(rule_file)
            removed_count += 1

    # Compile all remaining valid rules into a single file
    if files_to_compile:
        compiled_rules = yara.compile(filepaths=files_to_compile)
        compiled_rules.save(compiled_rules_path)
        print(f"All remaining rules compiled and saved into {compiled_rules_path}")

    # Print summary of compilation results
    print(f"Summary: {success_count} rules compiled successfully, {removed_count} rules removed due to errors.")

compile_yara_rules("/opt/sensoroni/yara/rules/")