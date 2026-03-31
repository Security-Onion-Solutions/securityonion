# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# when the salt-minion signs the cert, a copy is stored here
issued_certs_copypath:
  file.directory:
    - name: /etc/pki/issued_certs
    - makedirs: True

signing_policy:
  file.managed:
    - name: /etc/salt/minion.d/signing_policies.conf
    - source: salt://ca/files/signing_policies.conf
