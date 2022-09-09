# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}

# These values are generated during node install and stored in minion pillar
{% set SERVICETOKEN = salt['pillar.get']('elasticfleet:server:es_token','') %}
{% set FLEETSERVERPOLICY = salt['pillar.get']('elasticfleet:server:server_policy','so-manager') %}
{% set FLEETURL = salt['pillar.get']('elasticfleet:server:url') %}

elasticfleetdir:
  file.directory:
    - name: /opt/so/conf/elastic-fleet/state
    - makedirs: True

  {% if SERVICETOKEN != '' %}
so-elastic-fleet:
  docker_container.running:
    - image: docker.elastic.co/beats/elastic-agent:8.4.1
    - name: so-elastic-fleet
    - hostname: Fleet-{{ GLOBALS.hostname }}
    - detach: True
    - user: root
    - extra_hosts:
        - {{ GLOBALS.hostname }}:{{ GLOBALS.node_ip }}
    - port_bindings:
      - 0.0.0.0:8220:8220
    - binds:
      - /opt/so/conf/filebeat/etc/pki:/etc/pki:ro
      - /opt/so/conf/elastic-fleet/state:/usr/share/elastic-agent/state:rw
    - environment:
      - FLEET_SERVER_ENABLE=true
      - FLEET_URL=https://{{ FLEETURL }}:8220
      - FLEET_SERVER_ELASTICSEARCH_HOST=https://{{ GLOBALS.manager_ip }}:9200
      - FLEET_SERVER_SERVICE_TOKEN={{ SERVICETOKEN }}
      - FLEET_SERVER_POLICY_ID={{ FLEETSERVERPOLICY }}
      - FLEET_SERVER_ELASTICSEARCH_CA=/etc/pki/intca.crt
      - FLEET_SERVER_CERT=/etc/pki/filebeat.crt
      - FLEET_SERVER_CERT_KEY=/etc/pki/filebeat.key
      - FLEET_CA=/etc/pki/intca.crt
  {% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}