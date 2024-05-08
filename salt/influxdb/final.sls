# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

include:
  - influxdb.enabled

influxdb-setup:
  cmd.run:
    - name: /usr/sbin/so-influxdb-manage setup &>> /opt/so/log/influxdb/setup.log
    - require:
      - file: influxdbbucketsconf
      - file: influxdb_curl_config
      - docker_container: so-influxdb

metrics_link_file:
  cmd.run:
    - name: so-influxdb-manage dashboardpath "Security Onion Performance" > /opt/so/saltstack/local/salt/influxdb/metrics_link.txt
    - require:
      - docker_container: so-influxdb

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
