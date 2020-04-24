{% set GRAFANA = salt['pillar.get']('master:grafana', '0') %}
{% set MASTER = salt['grains.get']('master') %}
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.2') %}

{% if grains['role'] in ['so-master', 'so-mastersearch', 'so-eval'] and GRAFANA == 1 %}

# Grafana all the things
grafanadir:
  file.directory:
    - name: /nsm/grafana
    - user: 939
    - group: 939
    - makedirs: True

grafanaconfdir:
  file.directory:
    - name: /opt/so/conf/grafana/etc
    - user: 939
    - group: 939
    - makedirs: True

grafanadashdir:
  file.directory:
    - name: /opt/so/conf/grafana/grafana_dashboards
    - user: 939
    - group: 939
    - makedirs: True

grafanadashmdir:
  file.directory:
    - name: /opt/so/conf/grafana/grafana_dashboards/master
    - user: 939
    - group: 939
    - makedirs: True

grafanadashevaldir:
  file.directory:
    - name: /opt/so/conf/grafana/grafana_dashboards/eval
    - user: 939
    - group: 939
    - makedirs: True

grafanadashfndir:
  file.directory:
    - name: /opt/so/conf/grafana/grafana_dashboards/sensor_nodes
    - user: 939
    - group: 939
    - makedirs: True

grafanadashsndir:
  file.directory:
    - name: /opt/so/conf/grafana/grafana_dashboards/search_nodes
    - user: 939
    - group: 939
    - makedirs: True

grafanaconf:
  file.recurse:
    - name: /opt/so/conf/grafana/etc
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/etc

{% if salt['pillar.get']('mastertab', False) %}
{% for SN, SNDATA in salt['pillar.get']('mastertab', {}).items() %}
{% set NODETYPE = SN.split('_')|last %}
{% set SN = SN | regex_replace('_' ~ NODETYPE, '') %}
dashboard-master:
  file.managed:
    - name: /opt/so/conf/grafana/grafana_dashboards/master/{{ SN }}-Master.json
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/dashboards/master/master.json
    - defaults:
      SERVERNAME: {{ SN }}
      MANINT: {{ SNDATA.manint }}
      MONINT: {{ SNDATA.manint }}
      CPUS: {{ SNDATA.totalcpus }}
      UID: {{ SNDATA.guid }}
      ROOTFS: {{ SNDATA.rootfs }}
      NSMFS: {{ SNDATA.nsmfs }}

{% endfor %}
{% endif %}

{% if salt['pillar.get']('sensorstab', False) %}
{% for SN, SNDATA in salt['pillar.get']('sensorstab', {}).items() %}
{% set NODETYPE = SN.split('_')|last %}
{% set SN = SN | regex_replace('_' ~ NODETYPE, '') %}
dashboard-{{ SN }}:
  file.managed:
    - name: /opt/so/conf/grafana/grafana_dashboards/sensor_nodes/{{ SN }}-Sensor.json
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/dashboards/sensor_nodes/sensor.json
    - defaults:
      SERVERNAME: {{ SN }}
      MONINT: {{ SNDATA.monint }}
      MANINT: {{ SNDATA.manint }}
      CPUS: {{ SNDATA.totalcpus }}
      UID: {{ SNDATA.guid }}
      ROOTFS: {{ SNDATA.rootfs }}
      NSMFS: {{ SNDATA.nsmfs }}

{% endfor %}
{% endif %}

{% if salt['pillar.get']('nodestab', False) %}
{% for SN, SNDATA in salt['pillar.get']('nodestab', {}).items() %}
{% set NODETYPE = SN.split('_')|last %}
{% set SN = SN | regex_replace('_' ~ NODETYPE, '') %}
dashboardsearch-{{ SN }}:
  file.managed:
    - name: /opt/so/conf/grafana/grafana_dashboards/search_nodes/{{ SN }}-Node.json
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/dashboards/search_nodes/searchnode.json
    - defaults:
      SERVERNAME: {{ SN }}
      MANINT: {{ SNDATA.manint }}
      MONINT: {{ SNDATA.manint }}
      CPUS: {{ SNDATA.totalcpus }}
      UID: {{ SNDATA.guid }}
      ROOTFS: {{ SNDATA.rootfs }}
      NSMFS: {{ SNDATA.nsmfs }}

{% endfor %}
{% endif %}

{% if salt['pillar.get']('evaltab', False) %}
{% for SN, SNDATA in salt['pillar.get']('evaltab', {}).items() %}
{% set NODETYPE = SN.split('_')|last %}
{% set SN = SN | regex_replace('_' ~ NODETYPE, '') %}
dashboard-{{ SN }}:
  file.managed:
    - name: /opt/so/conf/grafana/grafana_dashboards/eval/{{ SN }}-Node.json
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/dashboards/eval/eval.json
    - defaults:
      SERVERNAME: {{ SN }}
      MANINT: {{ SNDATA.manint }}
      MONINT: {{ SNDATA.monint }}
      CPUS: {{ SNDATA.totalcpus }}
      UID: {{ SNDATA.guid }}
      ROOTFS: {{ SNDATA.rootfs }}
      NSMFS: {{ SNDATA.nsmfs }}

{% endfor %}
{% endif %}

so-grafana:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-grafana:{{ VERSION }}
    - hostname: grafana
    - user: socore
    - binds:
      - /nsm/grafana:/var/lib/grafana:rw
      - /opt/so/conf/grafana/etc/grafana.ini:/etc/grafana/grafana.ini:ro
      - /opt/so/conf/grafana/etc/datasources:/etc/grafana/provisioning/datasources:rw
      - /opt/so/conf/grafana/etc/dashboards:/etc/grafana/provisioning/dashboards:rw
      - /opt/so/conf/grafana/grafana_dashboards:/etc/grafana/grafana_dashboards:rw
    - environment:
      - GF_SECURITY_ADMIN_PASSWORD=augusta
    - port_bindings:
      - 0.0.0.0:3000:3000
    - watch:
      - file: /opt/so/conf/grafana/*

{% endif %}