# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'docker/docker.map.jinja' import DOCKER %}


include:
  - sensoroni.config
  - sensoroni.sostatus

so-sensoroni:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-soc:{{ GLOBALS.so_version }}
    - network_mode: host
    - binds:
      - /opt/so/conf/steno/certs:/etc/stenographer/certs:rw
      - /nsm/pcap:/nsm/pcap:rw
      - /nsm/import:/nsm/import:rw
      - /nsm/pcapout:/nsm/pcapout:rw
      - /opt/so/conf/sensoroni/sensoroni.json:/opt/sensoroni/sensoroni.json:ro
      - /opt/so/conf/sensoroni/analyzers:/opt/sensoroni/analyzers:rw
      - /opt/so/log/sensoroni:/opt/sensoroni/logs:rw
      - /nsm/suripcap/:/nsm/suripcap:rw
      {% if DOCKER.containers['so-sensoroni'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-sensoroni'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    {% if DOCKER.containers['so-sensoroni'].extra_hosts %}
    - extra_hosts:
      {% for XTRAHOST in DOCKER.containers['so-sensoroni'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    {% if DOCKER.containers['so-sensoroni'].extra_env %}
    - environment:
      {% for XTRAENV in DOCKER.containers['so-sensoroni'].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    - watch:
      - file: /opt/so/conf/sensoroni/sensoroni.json
    - require:
      - file: sensoroniagentconf

delete_so-sensoroni_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-sensoroni$
