{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'docker/docker.map.jinja' import DOCKER %}
{% from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - nginx

soctopusdir:
  file.directory:
    - name: /opt/so/conf/soctopus/sigma-import
    - user: 939
    - group: 939
    - makedirs: True

soctopus-sync:
  file.recurse:
    - name: /opt/so/conf/soctopus/templates
    - source: salt://soctopus/files/templates
    - user: 939
    - group: 939
    - template: jinja
    - defaults:
        GLOBALS: {{ GLOBALS }}

soctopusconf:
  file.managed:
    - name: /opt/so/conf/soctopus/SOCtopus.conf
    - source: salt://soctopus/files/SOCtopus.conf
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja
    - show_changes: False
    - defaults:
        GLOBALS: {{ GLOBALS }}

soctopuslogdir:
  file.directory:
    - name: /opt/so/log/soctopus
    - user: 939
    - group: 939

playbookrulesdir:
  file.directory:
    - name: /opt/so/rules/elastalert/playbook
    - user: 939
    - group: 939
    - makedirs: True

playbookrulessync:
  file.recurse:
    - name: /opt/so/rules/elastalert/playbook
    - source: salt://soctopus/files/templates
    - user: 939
    - group: 939
    - template: jinja
    - defaults:
        GLOBALS: {{ GLOBALS }}

so-soctopus:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-soctopus:{{ GLOBALS.so_version }}
    - hostname: soctopus
    - name: so-soctopus
    - networks:
      - sosnet:
        - ipv4_address: {{ DOCKER.containers['so-soctopus'].ip }}
    - binds:
      - /opt/so/conf/soctopus/SOCtopus.conf:/SOCtopus/SOCtopus.conf:ro
      - /opt/so/log/soctopus/:/var/log/SOCtopus/:rw
      - /opt/so/rules/elastalert/playbook:/etc/playbook-rules:rw
      - /opt/so/conf/navigator/nav_layer_playbook.json:/etc/playbook/nav_layer_playbook.json:rw
      - /opt/so/conf/soctopus/sigma-import/:/SOCtopus/sigma-import/:rw    
      {% if GLOBALS.airgap %}
      - /nsm/repo/rules/sigma:/soctopus/sigma
      {% endif %}
    - port_bindings:
      - 0.0.0.0:7000:7000
    - extra_hosts:
      - {{GLOBALS.url_base}}:{{GLOBALS.manager_ip}}
    - require:
      - file: soctopusconf
      - file: navigatordefaultlayer

append_so-soctopus_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-soctopus

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
