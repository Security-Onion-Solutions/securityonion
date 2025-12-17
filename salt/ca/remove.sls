# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% set setup_running = salt['cmd.retcode']('pgrep -x so-setup') == 0 %}

{% if setup_running%}

include:
  - ssl.remove

remove_pki_private_key:
  file.absent:
    - name: /etc/pki/ca.key

remove_pki_public_ca_crt:
  file.absent:
    - name: /etc/pki/ca.crt

remove_trusttheca:
  file.absent:
    - name: /etc/pki/tls/certs/intca.crt

remove_pki_public_ca_crt_symlink:
  file.absent:
    - name: /opt/so/saltstack/local/salt/ca/files/ca.crt

{% else %}

so-setup_not_running:
  test.show_notification:
    - text: "This state is reserved for usage during so-setup."

{% endif %}
