# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   set PASSWORD = salt['pillar.get']('secrets:influx_pass') %}
{%   set TOKEN = salt['pillar.get']('influxdb:token') %}

include:
  - influxdb.config
  - influxdb.sostatus

so-influxdb:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-influxdb:{{ GLOBALS.so_version }}
    - hostname: influxdb
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-influxdb'].ip }}
    - environment:
      - INFLUXD_CONFIG_PATH=/conf
      - INFLUXDB_HTTP_LOG_ENABLED=false
      - DOCKER_INFLUXDB_INIT_MODE=setup
      - DOCKER_INFLUXDB_INIT_USERNAME=so
      - DOCKER_INFLUXDB_INIT_PASSWORD={{ PASSWORD }}
      - DOCKER_INFLUXDB_INIT_ORG=Security Onion
      - DOCKER_INFLUXDB_INIT_BUCKET=telegraf/so_short_term
      - DOCKER_INFLUXDB_INIT_ADMIN_TOKEN={{ TOKEN }}
      {% if DOCKER.containers['so-influxdb'].extra_env %}
        {% for XTRAENV in DOCKER.containers['so-influxdb'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - binds:
      - /opt/so/log/influxdb/:/log:rw
      - /opt/so/conf/influxdb/config.yaml:/conf/config.yaml:ro
      - /opt/so/conf/influxdb/etc:/etc/influxdb2:rw
      - /nsm/influxdb:/var/lib/influxdb2:rw
      - /etc/pki/influxdb.crt:/conf/influxdb.crt:ro
      - /etc/pki/influxdb.key:/conf/influxdb.key:ro
      {% if DOCKER.containers['so-influxdb'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-influxdb'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-influxdb'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    {% if DOCKER.containers['so-influxdb'].extra_hosts %}
    - extra_hosts:
      {% for XTRAHOST in DOCKER.containers['so-influxdb'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    - watch:
      - file: influxdbconf
    - require:
      - file: influxdbconf
      - x509: influxdb_key
      - x509: influxdb_crt

delete_so-influxdb_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-influxdb$

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

# Install cron job to determine size of influxdb for telegraf
get_influxdb_size:
  cron.present:
    - name: 'du -s -k /nsm/influxdb | cut -f1 > /opt/so/log/telegraf/influxdb_size.log 2>&1'
    - identifier: get_influxdb_size
    - user: root
    - minute: '*/1'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
