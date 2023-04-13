{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'docker/docker.map.jinja' import DOCKER %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'influxdb/map.jinja' import INFLUXMERGED %}

{% if grains['role'] in ['so-manager', 'so-managersearch', 'so-standalone', 'so-eval', 'so-import'] %}
{% set PASSWORD = salt['pillar.get']('secrets:influx_pass') %}
{% set TOKEN = salt['pillar.get']('influxdb:token') %}

include:
  - salt.minion
  - ssl
  
# Influx DB
influxconfdir:
  file.directory:
    - name: /opt/so/conf/influxdb
    - makedirs: True

influxlogdir:
  file.directory:
    - name: /opt/so/log/influxdb
    - dir_mode: 755
    - user: 939
    - group: 939
    - makedirs: True

influxdbdir:
  file.directory:
    - name: /nsm/influxdb
    - makedirs: True

influxdbconf:
  file.managed:
    - name: /opt/so/conf/influxdb/config.yaml
    - source: salt://influxdb/config.yaml.jinja
    - user: 939
    - group: 939
    - template: jinja
    - defaults:
        INFLUXMERGED: {{ INFLUXMERGED }}

influxdbbucketsconf:
  file.managed:
    - name: /opt/so/conf/influxdb/buckets.json
    - source: salt://influxdb/buckets.json.jinja
    - user: 939
    - group: 939
    - template: jinja
    - defaults:
        INFLUXMERGED: {{ INFLUXMERGED }}

influxdb-templates:
  file.recurse:
    - name: /opt/so/conf/influxdb/templates
    - source: salt://influxdb/templates
    - user: 939
    - group: 939
    - template: jinja
    - clean: True
    - defaults:
        INFLUXMERGED: {{ INFLUXMERGED }}

influxdb_curl_config:
  file.managed:
    - name: /opt/so/conf/influxdb/curl.config
    - source: salt://influxdb/curl.config.jinja
    - mode: 600
    - template: jinja
    - show_changes: False
    - makedirs: True

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
    - binds:
      - /opt/so/log/influxdb/:/log:rw
      - /opt/so/conf/influxdb/config.yaml:/conf/config.yaml:ro
      - /nsm/influxdb:/var/lib/influxdb2:rw
      - /etc/pki/influxdb.crt:/conf/influxdb.crt:ro
      - /etc/pki/influxdb.key:/conf/influxdb.key:ro
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-influxdb'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - watch:
      - file: influxdbconf
    - require:
      - file: influxdbconf
      - x509: influxdb_key
      - x509: influxdb_crt

append_so-influxdb_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-influxdb

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

{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
