# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'salt/map.jinja' import SALTVERSION %}
{% from 'salt/map.jinja' import INSTALLEDSALTVERSION %}
{% from 'salt/map.jinja' import SYSTEMD_UNIT_FILE %}

include:
  - systemd.reload

{% if INSTALLEDSALTVERSION|string == SALTVERSION|string %}

# prior to 2.4.30 this managed file would restart the salt-minion service when updated
# since this file is currently only adding a delay service start
# it is not required to restart the service
salt_minion_service_unit_file:
  file.managed:
    - name: {{ SYSTEMD_UNIT_FILE }}
    - source: salt://salt/service/salt-minion.service.jinja
    - template: jinja
    - onchanges_in:
      - module: systemd_reload

{% endif %}
