# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKERMERGED %}
{%   from 'elasticsearch/config.map.jinja' import ELASTICSEARCH_NODES %}
{%   from 'elasticsearch/config.map.jinja' import ELASTICSEARCH_SEED_HOSTS %}
{%   from 'elasticsearch/config.map.jinja' import ELASTICSEARCHMERGED %}

include:
  - ca
  - elasticsearch.ca
  - elasticsearch.ssl
  - elasticsearch.config
  - elasticsearch.sostatus
{%- if GLOBALS.role != 'so-searchode' %}
  - elasticsearch.cluster
{%- endif%}

so-elasticsearch:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-elasticsearch:{{ ELASTICSEARCHMERGED.version }}
    - hostname: elasticsearch
    - name: so-elasticsearch
    - user: elasticsearch
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKERMERGED.containers['so-elasticsearch'].ip }}
    - extra_hosts:
    {% for node in ELASTICSEARCH_NODES %}
    {%   for hostname, ip in node.items() %}
      - {{hostname}}:{{ip}}
    {%   endfor %}
    {% endfor %}
    {% if DOCKERMERGED.containers['so-elasticsearch'].extra_hosts %}
      {% for XTRAHOST in DOCKERMERGED.containers['so-elasticsearch'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    - environment:
      {% if (GLOBALS.role in GLOBALS.manager_roles and ELASTICSEARCH_SEED_HOSTS | length == 1) or GLOBALS.role == 'so-heavynode' %}
      - discovery.type=single-node
      {% endif %}
      - ES_JAVA_OPTS=-Xms{{ GLOBALS.elasticsearch.es_heap }} -Xmx{{ GLOBALS.elasticsearch.es_heap }} -Des.transport.cname_in_publish_address=true -Dlog4j2.formatMsgNoLookups=true
      {% if DOCKERMERGED.containers['so-elasticsearch'].extra_env %}
        {% for XTRAENV in DOCKERMERGED.containers['so-elasticsearch'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    {% if DOCKERMERGED.containers['so-elasticsearch'].ulimits %}
    - ulimits:
    {%   for ULIMIT in DOCKERMERGED.containers['so-elasticsearch'].ulimits %}
      - {{ ULIMIT.name }}={{ ULIMIT.soft }}:{{ ULIMIT.hard }}
    {%   endfor %}
    {% endif %}
    - port_bindings:
      {% for BINDING in DOCKERMERGED.containers['so-elasticsearch'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - binds:
      - /opt/so/conf/elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro
      - /opt/so/conf/elasticsearch/log4j2.properties:/usr/share/elasticsearch/config/log4j2.properties:ro
      - /nsm/elasticsearch:/usr/share/elasticsearch/data:rw
      - /opt/so/log/elasticsearch:/var/log/elasticsearch:rw
      - /opt/so/conf/ca/cacerts:/usr/share/elasticsearch/jdk/lib/security/cacerts:ro
      - /etc/pki/tls/certs/intca.crt:/usr/share/elasticsearch/config/ca.crt:ro
      - /etc/pki/elasticsearch.crt:/usr/share/elasticsearch/config/elasticsearch.crt:ro
      - /etc/pki/elasticsearch.key:/usr/share/elasticsearch/config/elasticsearch.key:ro
      - /etc/pki/elasticsearch.p12:/usr/share/elasticsearch/config/elasticsearch.p12:ro
      - /opt/so/conf/elasticsearch/users_roles:/usr/share/elasticsearch/config/users_roles:ro
      - /opt/so/conf/elasticsearch/users:/usr/share/elasticsearch/config/users:ro
      {% if ELASTICSEARCHMERGED.config.path.get('repo', False) %}
        {% for repo in ELASTICSEARCHMERGED.config.path.repo %}
      - {{ repo }}:{{ repo }}:rw
        {% endfor %}
      {% endif %}
      {% if DOCKERMERGED.containers['so-elasticsearch'].custom_bind_mounts %}
        {% for BIND in DOCKERMERGED.containers['so-elasticsearch'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - watch:
      - file: trusttheca
      - x509: elasticsearch_crt
      - x509: elasticsearch_key
      - file: elasticsearch_cacerts
      - file: esyml
    - require:
      - file: trusttheca
      - x509: elasticsearch_crt
      - x509: elasticsearch_key
      - file: elasticsearch_cacerts
      - file: esyml
      - file: eslog4jfile
      - file: nsmesdir
      - file: eslogdir
      - file: elasticp12perms
      - cmd: auth_users_roles_inode
      - cmd: auth_users_inode

delete_so-elasticsearch_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-elasticsearch$

wait_for_so-elasticsearch:
  http.wait_for_successful_query:
    - name: "https://localhost:9200/"
    - username: 'so_elastic'
    - password: '{{ ELASTICSEARCHMERGED.auth.users.so_elastic_user.pass }}'
    - ssl: True
    - verify_ssl: False
    - status: 200
    - wait_for: 300
    - request_interval: 15
    - backend: requests
    - require:
      - docker_container: so-elasticsearch

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
