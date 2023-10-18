# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}


include:
  - ca.dirs

/etc/salt/minion.d/signing_policies.conf:
  file.managed:
    - source: salt://ca/files/signing_policies.conf

pki_private_key:
  x509.private_key_managed:
    - name: /etc/pki/ca.key
    - keysize: 4096
    - passphrase:
    - backup: True
    {% if salt['file.file_exists']('/etc/pki/ca.key') -%}
    - prereq:
      - x509: /etc/pki/ca.crt
    {%- endif %}

pki_public_ca_crt:
  x509.certificate_managed:
    - name: /etc/pki/ca.crt
    - signing_private_key: /etc/pki/ca.key
    - CN: {{ GLOBALS.manager }}
    - C: US
    - ST: Utah
    - L: Salt Lake City
    - basicConstraints: "critical CA:true"
    - keyUsage: "critical cRLSign, keyCertSign"
    - extendedkeyUsage: "serverAuth, clientAuth"
    - subjectKeyIdentifier: hash
    - authorityKeyIdentifier: keyid:always, issuer
    - days_valid: 3650
    - days_remaining: 0
    - backup: True
    - replace: False
    - require:
      - sls: ca.dirs
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

mine_update_ca_crt:
  module.run:
    - mine.update: []
    - onchanges:
      - file: pki_public_ca_crt

cakeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/ca.key
    - mode: 640
    - group: 939

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
