# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - pcap.config
  - pcap.sostatus

so-steno:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-steno:{{ GLOBALS.so_version }}
    - start: True
    - network_mode: host
    - privileged: True
    - binds:
      - /opt/so/conf/steno/certs:/etc/stenographer/certs:rw
      - /opt/so/conf/steno/config:/etc/stenographer/config:rw
      - /nsm/pcap:/nsm/pcap:rw
      - /nsm/pcapindex:/nsm/pcapindex:rw
      - /nsm/pcaptmp:/tmp:rw
      - /opt/so/log/stenographer:/var/log/stenographer:rw
    - watch:
      - file: stenoconf
    - require:
      - file: stenoconf

delete_so-steno_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-steno$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
