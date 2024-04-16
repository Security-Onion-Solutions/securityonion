# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import os
import yara
import glob
import sys

def compile_yara_rules(rules_dir: str) -> None:
		compiled_rules_path: str = os.path.join(rules_dir, "rules.yar.compiled")
		rule_files: list[str] = glob.glob(os.path.join(rules_dir, '**/*.yar'), recursive=True)

		if rule_files:
				rules: yara.Rules = yara.compile(filepaths={os.path.basename(f): f for f in rule_files})
				rules.save(compiled_rules_path)

compile_yara_rules(sys.argv[1])
