# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'suricata/map.jinja' import SURICATAMERGED %}


include:
  - suricata.config
  - suricata.sostatus

so-suricata:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-suricata:{{ GLOBALS.so_version }}
    - privileged: True
    - environment:
      - INTERFACE={{ GLOBALS.sensor.interface }}
      {% if DOCKER.containers['so-suricata'].extra_env %}
        {% for XTRAENV in DOCKER.containers['so-suricata'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    {# we look at SURICATAMERGED.config['af-packet'][0] since we only allow one interface and therefore always the first list item #}
    {% if SURICATAMERGED.config['af-packet'][0]['mmap-locked'] == "yes" and DOCKER.containers['so-suricata'].ulimits %}
    - ulimits:
    {%   for ULIMIT in DOCKER.containers['so-suricata'].ulimits %}
      - {{ ULIMIT }}
    {%   endfor %}
    {% endif %}
    - binds:
      - /opt/so/conf/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro
      - /opt/so/conf/suricata/threshold.conf:/etc/suricata/threshold.conf:ro
      - /opt/so/conf/suricata/classification.config:/etc/suricata/classification.config:ro
      - /opt/so/conf/suricata/rules:/etc/suricata/rules:ro
      - /opt/so/log/suricata/:/var/log/suricata/:rw
      - /nsm/suricata/:/nsm/:rw
      - /nsm/suricata/extracted:/var/log/suricata//filestore:rw
      - /opt/so/conf/suricata/bpf:/etc/suricata/bpf:ro
      - /nsm/suripcap/:/nsm/suripcap:rw
      {% if DOCKER.containers['so-suricata'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-suricata'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - network_mode: host
    {% if DOCKER.containers['so-suricata'].extra_hosts %}
    - extra_hosts:
      {% for XTRAHOST in DOCKER.containers['so-suricata'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    - watch:
      - file: suriconfig
      - file: surithresholding
      - file: /opt/so/conf/suricata/rules/
      - file: /opt/so/conf/suricata/bpf
      - file: suriclassifications
    - require:
      - file: suriconfig
      - file: surithresholding
      - file: suribpf
      - file: suriclassifications

delete_so-suricata_so-status.disabled:
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
