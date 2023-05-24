# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - suricata.config
  - suricata.sostatus

so-suricata:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-suricata:{{ GLOBALS.so_version }}
    - privileged: True
    - environment:
      - INTERFACE={{ GLOBALS.sensor.interface }}
    - binds:
      - /opt/so/conf/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro
      - /opt/so/conf/suricata/threshold.conf:/etc/suricata/threshold.conf:ro
      - /opt/so/conf/suricata/rules:/etc/suricata/rules:ro
      - /opt/so/log/suricata/:/var/log/suricata/:rw
      - /nsm/suricata/:/nsm/:rw
      - /nsm/suricata/extracted:/var/log/suricata//filestore:rw
      - /opt/so/conf/suricata/bpf:/etc/suricata/bpf:ro
    - network_mode: host
    - watch:
      - file: suriconfig
      - file: surithresholding
      - file: /opt/so/conf/suricata/rules/
      - file: /opt/so/conf/suricata/bpf
    - require:
      - file: suriconfig
      - file: surithresholding
      - file: suribpf

delete_so-kibana_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-suricata$

# Add eve clean cron
clean_suricata_eve_files:
  cron.present:
    - name: /usr/sbin/so-suricata-eve-clean > /dev/null 2>&1
    - identifier: clean_suricata_eve_files
    - user: root
    - minute: '*/5'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
