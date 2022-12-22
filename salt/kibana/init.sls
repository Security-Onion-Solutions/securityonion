# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'docker/docker.map.jinja' import DOCKER %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
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

kibanaconfig:
  file.managed:
    - name: /opt/so/conf/kibana/etc/kibana.yml
    - source: salt://kibana/etc/kibana.yml.jinja
    - user: 932
    - group: 939
    - mode: 660
    - template: jinja
    - defaults:
        KIBANACONFIG: {{ KIBANACONFIG }}
    - show_changes: False

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
    - name: /usr/sbin/so-kibana-config-load
    - source: salt://kibana/bin/so-kibana-config-load
    - mode: 755
    - template: jinja
    - defaults:
        GLOBALS: {{ GLOBALS }}

# Start the kibana docker
so-kibana:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-kibana:{{ GLOBALS.so_version }}
    - hostname: kibana
    - user: kibana
    - networks:
      - sosbridge:
        - ipv4_address: {{ DOCKER.containers['so-kibana'].ip }}
    - environment:
      - ELASTICSEARCH_HOST={{ GLOBALS.manager }}
      - ELASTICSEARCH_PORT=9200
      - MANAGER={{ GLOBALS.manager }}
    - binds:
      - /opt/so/conf/kibana/etc:/usr/share/kibana/config:rw
      - /opt/so/log/kibana:/var/log/kibana:rw
      - /opt/so/conf/kibana/customdashboards:/usr/share/kibana/custdashboards:ro
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
    - port_bindings:
      - 0.0.0.0:5601:5601
    - watch:
      - file: kibanaconfig

append_so-kibana_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-kibana

osquery_hunt_link:
  cmd.script:
    - source: salt://kibana/files/live_query_fixup.sh
    - cwd: /root
    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
