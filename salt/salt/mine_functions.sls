# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# this state was separated from salt.minion state since it is called during setup
# GLOBALS are imported in the salt.minion state and that is not available at that point in setup
# this state is included in the salt.minion state

{% from 'salt/map.jinja' import interface %}
{% from 'salt/map.jinja' import role %}

mine_functions:
  file.managed:
    - name: /etc/salt/minion.d/mine_functions.conf
    - contents: |
        mine_interval: 25
        mine_functions:
          network.ip_addrs:
            - interface: {{ interface }}
        {%- if role in ['so-eval','so-import','so-manager','so-managerhype','so-managersearch','so-standalone'] %}
          x509.get_pem_entries:
            - glob_path: '/etc/pki/ca.crt'
        {% endif %}

mine_update_mine_functions:
  module.run:
    - mine.update: []
    - onchanges:
      - file: mine_functions
    - onlyif:
      - systemctl is-active --quiet salt-minion
    {%- if role in ['so-eval','so-import','so-manager','so-managerhype','so-managersearch','so-standalone'] %}
      - systemctl is-active --quiet salt-master
    {% endif %}
