{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% from 'elasticsearch/auth.map.jinja' import ELASTICAUTH with context %}

{% import_yaml 'kibana/defaults.yaml' as default_settings %}
{% set KIBANA_SETTINGS = salt['grains.filter_by'](default_settings, default='kibana', merge=salt['pillar.get']('kibana', {})) %}

{% from 'kibana/config.map.jinja' import KIBANACONFIG with context %}

# Add ES Group
kibanasearchgroup:
  group.present:
    - name: kibana
    - gid: 932

# Add ES user
kibana:
  user.present:
    - uid: 932
    - gid: 932
    - home: /opt/so/conf/kibana
    - createhome: False

# Drop the correct nginx config based on role

kibanaconfdir:
  file.directory:
    - name: /opt/so/conf/kibana/etc
    - user: 932
    - group: 939
    - makedirs: True

synckibanaconfig:
  file.managed:
    - name: /opt/so/conf/kibana/etc/kibana.yml
    - source: salt://kibana/etc/kibana.yml.jinja
    - user: 932
    - group: 939
    - mode: 660
    - template: jinja
    - defaults:
        KIBANACONFIG: {{ KIBANACONFIG }}

kibanalogdir:
  file.directory:
    - name: /opt/so/log/kibana
    - user: 932
    - group: 939
    - makedirs: True

kibanacustdashdir:
  file.directory:
    - name: /opt/so/conf/kibana/customdashboards
    - user: 932
    - group: 939
    - makedirs: True

synckibanacustom:
  file.recurse:
    - name: /opt/so/conf/kibana/customdashboards
    - source: salt://kibana/custom
    - user: 932
    - group: 939

kibanabin:
  file.managed:
    - name: /usr/sbin/so-kibana-dashboard-load
    - source: salt://kibana/bin/so-kibana-dashboard-load
    - mode: 755
    - template: jinja
    - defaults:
        ELASTICCURL: {{ ELASTICAUTH.elasticcurl }}

# Start the kibana docker
so-kibana:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-kibana:{{ VERSION }}
    - hostname: kibana
    - user: kibana
    - environment:
      - ELASTICSEARCH_HOST={{ MANAGER }}
      - ELASTICSEARCH_PORT=9200
      - MANAGER={{ MANAGER }}
    - binds:
      - /opt/so/conf/kibana/etc:/usr/share/kibana/config:rw
      - /opt/so/log/kibana:/var/log/kibana:rw
      - /opt/so/conf/kibana/customdashboards:/usr/share/kibana/custdashboards:ro
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
    - port_bindings:
      - 0.0.0.0:5601:5601

append_so-kibana_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-kibana

kibanadashtemplate:
  file.managed:
    - name: /opt/so/conf/kibana/saved_objects.ndjson.template
    - source: salt://kibana/files/saved_objects.ndjson.jinja
    - user: 932
    - group: 939
    - template: jinja
    - defaults:
        DASHBOARD: {{ KIBANA_SETTINGS.dashboard }}

so-kibana-dashboard-load:
  cmd.run:
    - name: /usr/sbin/so-kibana-dashboard-load
    - cwd: /opt/so

# Keep the setting correct
#KibanaHappy:
#  cmd.script:
#    - shell: /bin/bash
#    - runas: socore
#    - source: salt://kibana/bin/keepkibanahappy.sh
#    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
