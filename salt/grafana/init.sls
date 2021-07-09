{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set GRAFANA = salt['pillar.get']('manager:grafana', '0') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set ADMINPASS = salt['pillar.get']('secrets:grafana_admin') %}

{% import_yaml 'grafana/defaults.yaml' as default_settings %}
{% set GRAFANA_SETTINGS = salt['grains.filter_by'](default_settings, default='grafana', merge=salt['pillar.get']('grafana', {})) %}


{% if grains['role'] in ['so-manager', 'so-managersearch', 'so-standalone'] or (grains.role == 'so-eval' and GRAFANA == 1) %}

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
    - name: /opt/so/conf/grafana/grafana_dashboards/manager
    - user: 939
    - group: 939
    - makedirs: True

grafanadashmsdir:
  file.directory:
    - name: /opt/so/conf/grafana/grafana_dashboards/managersearch
    - user: 939
    - group: 939
    - makedirs: True

grafanadashsadir:
  file.directory:
    - name: /opt/so/conf/grafana/grafana_dashboards/standalone
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

grafana-dashboard-config:
  file.managed:
    - name: /opt/so/conf/grafana/etc/dashboards/dashboard.yml
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/etc/dashboards/dashboard.yml
    - makedirs: True


grafana-datasources-config:
  file.managed:
    - name: /opt/so/conf/grafana/etc/datasources/influxdb.yaml
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/etc/datasources/influxdb.yaml
    - makedirs: True

grafana-config:
  file.managed:
    - name: /opt/so/conf/grafana/etc/grafana.ini
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/etc/grafana.ini.jinja
    - context:
        config: {{ GRAFANA_SETTINGS.config|json }}

# these are the files that are referenced inside the config such as smtp:cert_file, smtp:cert_key, auth.ldap:config_file, enterprise:license_path
grafana-config-files:
  file.recurse:
    - name: /opt/so/conf/grafana/etc/files
    - user: 939
    - group: 939
    - source: salt://grafana/etc/files
    - makedirs: True
       
common-standalone-dashboard:
  file.managed:
    - name: /opt/so/conf/grafana/grafana_dashboards/standalone/common_standalone.json
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://grafana/dashboards/common_template.json.jinja
    - defaults:
        UID: so_overview
        PANELS: {{GRAFANA_SETTINGS.dashboards.standalone.panels}}
        TEMPLATES: {{GRAFANA_SETTINGS.dashboards.standalone.templating.list}}

so-grafana:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-grafana:{{ VERSION }}
    - hostname: grafana
    - user: socore
    - binds:
      - /nsm/grafana:/var/lib/grafana:rw
      - /opt/so/conf/grafana/etc/grafana.ini:/etc/grafana/grafana.ini:ro
      - /opt/so/conf/grafana/etc/datasources:/etc/grafana/provisioning/datasources:rw
      - /opt/so/conf/grafana/etc/dashboards:/etc/grafana/provisioning/dashboards:rw
      - /opt/so/conf/grafana/grafana_dashboards:/etc/grafana/grafana_dashboards:rw
      - /opt/so/conf/grafana/etc/files:/etc/grafana/config/files:ro
    - environment:
      - GF_SECURITY_ADMIN_PASSWORD={{ ADMINPASS }}
    - port_bindings:
      - 0.0.0.0:3000:3000
    - watch:
      - file: /opt/so/conf/grafana/*

append_so-grafana_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-grafana

{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
