# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'docker/docker.map.jinja' import DOCKER %}
{% from 'elastalert/elastalert_config.map.jinja' import ELASTALERT as elastalert_config with context %}

# Create the group
elastagroup:
  group.present:
    - name: elastalert
    - gid: 933

# Add user
elastalert:
  user.present:
    - uid: 933
    - gid: 933
    - home: /opt/so/conf/elastalert
    - createhome: False

elastalogdir:
  file.directory:
    - name: /opt/so/log/elastalert
    - user: 933
    - group: 933
    - makedirs: True

elastarules:
  file.directory:
    - name: /opt/so/rules/elastalert
    - user: 933
    - group: 933
    - makedirs: True

elastaconfdir:
  file.directory:
    - name: /opt/so/conf/elastalert
    - user: 933
    - group: 933
    - makedirs: True

elastasomodulesdir:
  file.directory:
    - name: /opt/so/conf/elastalert/modules/so
    - user: 933
    - group: 933
    - makedirs: True

elastacustmodulesdir:
  file.directory:
    - name: /opt/so/conf/elastalert/modules/custom
    - user: 933
    - group: 933
    - makedirs: True

elastasomodulesync:
  file.recurse:
    - name: /opt/so/conf/elastalert/modules/so
    - source: salt://elastalert/files/modules/so
    - user: 933
    - group: 933
    - makedirs: True

elastaconf:
  file.managed:
    - name: /opt/so/conf/elastalert/elastalert_config.yaml
    - source: salt://elastalert/files/elastalert_config.yaml.jinja
    - context:
        elastalert_config: {{ elastalert_config.elastalert.config }}
    - user: 933
    - group: 933
    - mode: 660
    - template: jinja
    - show_changes: False

wait_for_elasticsearch:
  cmd.run:
    - name: so-elasticsearch-wait

so-elastalert:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-elastalert:{{ GLOBALS.so_version }}
    - hostname: elastalert
    - name: so-elastalert
    - user: so-elastalert
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-elastalert'].ip }}
    - detach: True
    - binds:
      - /opt/so/rules/elastalert:/opt/elastalert/rules/:ro
      - /opt/so/log/elastalert:/var/log/elastalert:rw
      - /opt/so/conf/elastalert/modules/:/opt/elastalert/modules/:ro
      - /opt/so/conf/elastalert/elastalert_config.yaml:/opt/elastalert/config.yaml:ro
    - extra_hosts:
      - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
    - require:
      - cmd: wait_for_elasticsearch
      - file: elastarules
      - file: elastalogdir
      - file: elastacustmodulesdir
      - file: elastaconf
    - watch:
      - file: elastaconf
    - onlyif:
      - "so-elasticsearch-query / | jq -r '.version.number[0:1]' | grep -q 8" {# only run this state if elasticsearch is version 8 #}


append_so-elastalert_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-elastalert

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
