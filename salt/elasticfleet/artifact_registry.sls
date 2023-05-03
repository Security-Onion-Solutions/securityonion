# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.


fleetartifactdir:
  file.directory:
    - name: /nsm/elastic-fleet/artifacts
    - user: 947
    - group: 939
    - makedirs: True
