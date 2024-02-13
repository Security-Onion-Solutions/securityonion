# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'elasticfleet/map.jinja' import ELASTICFLEETMERGED %}

{#   This value is generated during node install and stored in minion pillar #}
{%   set SERVICETOKEN = salt['pillar.get']('elasticfleet:config:server:es_token','') %}

include:
  - elasticfleet.config
  - elasticfleet.sostatus
  - ssl

# Wait for Elasticsearch to be ready - no reason to try running Elastic Fleet server if ES is not ready
wait_for_elasticsearch_elasticfleet:
  cmd.run:
    - name: so-elasticsearch-wait

# If enabled, automatically update Fleet Logstash Outputs
{% if ELASTICFLEETMERGED.config.server.enable_auto_configuration and grains.role not in ['so-import', 'so-eval', 'so-fleet'] %}
so-elastic-fleet-auto-configure-logstash-outputs:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-outputs-update
    - retry: True
{% endif %}

# If enabled, automatically update Fleet Server URLs & ES Connection
{% if ELASTICFLEETMERGED.config.server.enable_auto_configuration and grains.role not in ['so-fleet'] %}
so-elastic-fleet-auto-configure-server-urls:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-urls-update
    - retry: True
{% endif %}

# Automatically update Fleet Server Elasticsearch URLs & Agent Artifact URLs
{% if grains.role not in ['so-fleet'] %}
so-elastic-fleet-auto-configure-elasticsearch-urls:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-es-url-update
    - retry: True

so-elastic-fleet-auto-configure-artifact-urls:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-artifacts-url-update
    - retry: True 

{% endif %}

# Sync Elastic Agent artifacts to Fleet Node
{% if grains.role in ['so-fleet'] %}
elasticagent_syncartifacts:
  file.recurse:
    - name: /nsm/elastic-fleet/artifacts/beats
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
        - ipv4_address: {{ DOCKER.containers['so-elastic-fleet'].ip }}
    - extra_hosts:
        - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
        - {{ GLOBALS.hostname }}:{{ GLOBALS.node_ip }}
        {% if DOCKER.containers['so-elastic-fleet'].extra_hosts %}
          {% for XTRAHOST in DOCKER.containers['so-elastic-fleet'].extra_hosts %}
        - {{ XTRAHOST }}
          {% endfor %}
        {% endif %}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-elastic-fleet'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - binds:
      - /etc/pki/elasticfleet-server.crt:/etc/pki/elasticfleet-server.crt:ro
      - /etc/pki/elasticfleet-server.key:/etc/pki/elasticfleet-server.key:ro
      - /etc/pki/tls/certs/intca.crt:/etc/pki/tls/certs/intca.crt:ro
      - /opt/so/log/elasticfleet:/usr/share/elastic-agent/logs 
     {% if DOCKER.containers['so-elastic-fleet'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-elastic-fleet'].custom_bind_mounts %}
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
      {% if DOCKER.containers['so-elastic-fleet'].extra_env %}
        {% for XTRAENV in DOCKER.containers['so-elastic-fleet'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - watch:
      - x509: etc_elasticfleet_key
      - x509: etc_elasticfleet_crt
{%   endif %}

{%  if GLOBALS.role != "so-fleet" %}
so-elastic-fleet-package-statefile:
  file.managed:
    - name: /opt/so/state/elastic_fleet_packages.txt
    - contents: {{ELASTICFLEETMERGED.packages}}

so-elastic-fleet-package-upgrade:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-package-upgrade
    - onchanges:
      - file: /opt/so/state/elastic_fleet_packages.txt

so-elastic-fleet-integrations:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-integration-policy-load

so-elastic-agent-grid-upgrade:
  cmd.run:
    - name: /usr/sbin/so-elastic-agent-grid-upgrade
    - retry: True
{%  endif %}

delete_so-elastic-fleet_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-elastic-fleet$


{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
