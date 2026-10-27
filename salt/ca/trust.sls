# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

ca_trust_anchor:
  file.managed:
    - name: /etc/pki/ca-trust/source/anchors/so-intca.crt
    - source: salt://ca/files/ca.crt
    - show_changes: False
    - makedirs: True

ca_trust_legacy_anchor:
  file.absent:
    - name: /etc/pki/ca-trust/source/anchors/ca.crt

ca_trust_legacy_bundles:
  file.absent:
    - name: /opt/so/conf/ca

# clean removes blocklist entries that are no longer shipped
ca_trust_blocklist:
  file.recurse:
    - name: /etc/pki/ca-trust/source/blocklist
    - source: salt://ca/files/blocklist
    - clean: True
    - makedirs: True
    - file_mode: '0644'
    - dir_mode: '0755'

ca_trust_extract:
  cmd.run:
    - name: update-ca-trust extract
    - onchanges:
      - file: ca_trust_anchor
      - file: ca_trust_legacy_anchor
      - file: ca_trust_blocklist
