{% set GRAFANA = salt['pillar.get']('manager:grafana', '0') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.2') %}


{% if grains['role'] in ['so-manager', 'so-managersearch', 'so-eval', 'so-standalone'] and GRAFANA == 1 %}

# Influx DB
influxconfdir:
  file.directory:
    - name: /opt/so/conf/influxdb/etc
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
    - image: {{ MANAGER }}:5000/soshybridhunter/so-influxdb:{{ VERSION }}
    - hostname: influxdb
    - environment:
      - INFLUXDB_HTTP_LOG_ENABLED=false
    - binds:
      - /opt/so/conf/influxdb/etc/influxdb.conf:/etc/influxdb/influxdb.conf:ro
      - /nsm/influxdb:/var/lib/influxdb:rw
      - /etc/pki/influxdb.crt:/etc/ssl/influxdb.crt:ro
      - /etc/pki/influxdb.key:/etc/ssl/influxdb.key:ro
    - port_bindings:
      - 0.0.0.0:8086:8086
    - watch:
      - file: influxdbconf

{% endif %}