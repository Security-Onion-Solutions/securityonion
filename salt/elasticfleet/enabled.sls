# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKERMERGED %}
{%   from 'elasticfleet/map.jinja' import ELASTICFLEETMERGED %}

{#   This value is generated during node install and stored in minion pillar #}
{%   set SERVICETOKEN = salt['pillar.get']('elasticfleet:config:server:es_token','') %}

include:
  - ca
  - logstash.ssl
  - elasticfleet.config
  - elasticfleet.sostatus
{%- if GLOBALS.role != "so-fleet" %}
  - elasticfleet.manager
{%- endif %}

{% if GLOBALS.role not in ['so-fleet'] %}
# Wait for Elasticsearch to be ready - no reason to try running Elastic Fleet server if ES is not ready
wait_for_elasticsearch_elasticfleet:
  cmd.run:
    - name: so-elasticsearch-wait

# Sync Elastic Agent artifacts to Fleet Node
elasticagent_syncartifacts:
  file.recurse:
    - name: /nsm/elastic-fleet/artifacts/beats
    - user: 947
    - group: 947
    - source: salt://beats
{% endif %}

{%   if SERVICETOKEN != '' %}
so-elastic-fleet:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-elastic-agent:{{ GLOBALS.so_version }}
    - name: so-elastic-fleet
    - hostname: FleetServer-{{ GLOBALS.hostname }}
    - detach: True
    - user: 947
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKERMERGED.containers['so-elastic-fleet'].ip }}
    - extra_hosts:
        - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
        - {{ GLOBALS.hostname }}:{{ GLOBALS.node_ip }}
        {% if DOCKERMERGED.containers['so-elastic-fleet'].extra_hosts %}
          {% for XTRAHOST in DOCKERMERGED.containers['so-elastic-fleet'].extra_hosts %}
        - {{ XTRAHOST }}
          {% endfor %}
        {% endif %}
    - port_bindings:
      {% for BINDING in DOCKERMERGED.containers['so-elastic-fleet'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - binds:
      - /etc/pki/elasticfleet-server.crt:/etc/pki/elasticfleet-server.crt:ro
      - /etc/pki/elasticfleet-server.key:/etc/pki/elasticfleet-server.key:ro
      - /etc/pki/tls/certs/intca.crt:/etc/pki/tls/certs/intca.crt:ro
      - /opt/so/log/elasticfleet:/usr/share/elastic-agent/logs 
     {% if DOCKERMERGED.containers['so-elastic-fleet'].custom_bind_mounts %}
        {% for BIND in DOCKERMERGED.containers['so-elastic-fleet'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}      
    - environment:
      - FLEET_SERVER_ENABLE=true
      - FLEET_URL=https://{{ GLOBALS.hostname }}:8220
      - FLEET_SERVER_ELASTICSEARCH_HOST=https://{{ GLOBALS.manager }}:9200
      - FLEET_SERVER_SERVICE_TOKEN={{ SERVICETOKEN }}
      - FLEET_SERVER_POLICY_ID=FleetServer_{{ GLOBALS.hostname }}
      - FLEET_SERVER_CERT=/etc/pki/elasticfleet-server.crt
      - FLEET_SERVER_CERT_KEY=/etc/pki/elasticfleet-server.key
      - FLEET_CA=/etc/pki/tls/certs/intca.crt     
      - FLEET_SERVER_ELASTICSEARCH_CA=/etc/pki/tls/certs/intca.crt
      - LOGS_PATH=logs
      {% if DOCKERMERGED.containers['so-elastic-fleet'].extra_env %}
        {% for XTRAENV in DOCKERMERGED.containers['so-elastic-fleet'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    {% if DOCKERMERGED.containers['so-elastic-fleet'].ulimits %}
    - ulimits:
    {%   for ULIMIT in DOCKERMERGED.containers['so-elastic-fleet'].ulimits %}
      - {{ ULIMIT.name }}={{ ULIMIT.soft }}:{{ ULIMIT.hard }}
    {%   endfor %}
    {% endif %}
    - watch:
      - file: trusttheca
      - x509: etc_elasticfleet_key
      - x509: etc_elasticfleet_crt
    - require:
      - file: trusttheca
      - x509: etc_elasticfleet_key
      - x509: etc_elasticfleet_crt
{%   endif %}

delete_so-elastic-fleet_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-elastic-fleet$


{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
