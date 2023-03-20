# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'docker/docker.map.jinja' import DOCKER %}

# These values are generated during node install and stored in minion pillar
{% set SERVICETOKEN = salt['pillar.get']('elasticfleet:server:es_token','') %}
{% set FLEETSERVERPOLICY = salt['pillar.get']('elasticfleet:server:server_policy','so-manager') %}
{% set FLEETURL = salt['pillar.get']('elasticfleet:server:url') %}

# Add EA Group
elasticsagentgroup:
  group.present:
    - name: elastic-agent
    - gid: 947

# Add EA user
elastic-agent:
  user.present:
    - uid: 947
    - gid: 947
    - home: /opt/so/conf/elastic-fleet
    - createhome: False

eaconfdir:
  file.directory:
    - name: /opt/so/conf/elastic-fleet
    - user: 947
    - group: 939
    - makedirs: True

eastatedir:
  file.directory:
    - name: /opt/so/conf/elastic-fleet/state
    - user: 947
    - group: 939
    - makedirs: True


  {% if SERVICETOKEN != '' %}
so-elastic-fleet:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-elastic-agent:{{ GLOBALS.so_version }}
    - name: so-elastic-fleet
    - hostname: Fleet-{{ GLOBALS.hostname }}
    - detach: True
    - user: 947
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-elastic-fleet'].ip }}
    - extra_hosts:
    {% if GLOBALS.is_manager %}
        - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
    {% else %}
        - {{ GLOBALS.hostname }}:{{ GLOBALS.node_ip }}
    {% endif %}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-elastic-fleet'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - binds:
      - /opt/so/conf/elastic-fleet/certs:/etc/pki:ro
      - /opt/so/conf/elastic-fleet/state:/usr/share/elastic-agent/state:rw
    - environment:
      - FLEET_SERVER_ENABLE=true
      - FLEET_URL=https://{{ FLEETURL }}:8220
      - FLEET_SERVER_ELASTICSEARCH_HOST=https://{{ GLOBALS.manager }}:9200
      - FLEET_SERVER_SERVICE_TOKEN={{ SERVICETOKEN }}
      - FLEET_SERVER_POLICY_ID={{ FLEETSERVERPOLICY }}
      - FLEET_SERVER_ELASTICSEARCH_CA=/etc/pki/intca.crt
      - FLEET_SERVER_CERT=/etc/pki/elasticfleet.crt
      - FLEET_SERVER_CERT_KEY=/etc/pki/elasticfleet.key
      - FLEET_CA=/etc/pki/intca.crt
  {% endif %}

append_so-elastic-fleet_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-elastic-fleet

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
