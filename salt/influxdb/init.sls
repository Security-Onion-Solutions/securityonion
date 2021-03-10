{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set GRAFANA = salt['pillar.get']('manager:grafana', '0') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% import_yaml 'influxdb/defaults.yaml' as default_settings %}
{% set influxdb = salt['grains.filter_by'](default_settings, default='influxdb', merge=salt['pillar.get']('influxdb', {})) %}

{% if grains['role'] in ['so-manager', 'so-managersearch', 'so-eval', 'so-standalone'] and GRAFANA == 1 %}

# Influx DB
influxconfdir:
  file.directory:
    - name: /opt/so/conf/influxdb/etc
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
    - name: /opt/so/conf/influxdb/etc/influxdb.conf
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://influxdb/etc/influxdb.conf

so-influxdb:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-influxdb:{{ VERSION }}
    - hostname: influxdb
    - environment:
      - INFLUXDB_HTTP_LOG_ENABLED=false
    - binds:
      - /opt/so/log/influxdb/:/log:rw
      - /opt/so/conf/influxdb/etc/influxdb.conf:/etc/influxdb/influxdb.conf:ro
      - /nsm/influxdb:/var/lib/influxdb:rw
      - /etc/pki/influxdb.crt:/etc/ssl/influxdb.crt:ro
      - /etc/pki/influxdb.key:/etc/ssl/influxdb.key:ro
    - port_bindings:
      - 0.0.0.0:8086:8086
    - watch:
      - file: influxdbconf

append_so-influxdb_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-influxdb

{% for rp in influxdb.retention_policies.keys() %}
{{rp}}_retention_policy:
  influxdb_retention_policy.present:
    - name: {{rp}}
    - database: telegraf
    - duration: {{influxdb.retention_policies[rp].duration}}
    - replication: 1
    - default: {{influxdb.retention_policies[rp].get('default', 'False')}}
    - ssl: True
    - require:
      - docker_container: so-influxdb
{% endfor %}

{% for dest_rp in influxdb.downsample.keys() %}
  {% for measurement in influxdb.downsample[dest_rp].measurements %}
so_downsample_{{measurement}}_cq:
  influxdb_continuous_query.present:
    - name: so_downsample_{{measurement}}_cq
    - database: telegraf
    - query: SELECT mean(*) INTO "{{dest_rp}}"."{{measurement}}" FROM "{{measurement}}" GROUP BY time({{influxdb.downsample[dest_rp].resolution}})
    - ssl: True
    - require:
      - docker_container: so-influxdb
  {% endfor %}
{% endfor %}

{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}

influxdb:
  retention_policies:
    autogen:
      default: True
      duration: 1h
    so_long_term:
      default: False
      duration: 2h
  downsample:
    so_long_term:
      resolution: 30m
      measurements:
        - cpu
        - disk
        - diskio
        - docker_container_cpu
        - docker_container_mem
        - docker_container_net
        - elasticsearch_indices
        - elasticsearch_jvm
        - esteps
        - healthcheck
        - influxsize
        - mem
        - net
        - pcapage
        - processes
        - redisqueue
        - stenodrop
        - suridrop
        - system
        - zeekcaptureloss
        - zeekdrop