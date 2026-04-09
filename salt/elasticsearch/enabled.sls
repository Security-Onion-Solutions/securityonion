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
{%   from 'elasticsearch/template.map.jinja' import ES_INDEX_SETTINGS, ALL_ADDON_SETTINGS, SO_MANAGED_INDICES %}

include:
  - ca
  - elasticsearch.ca
  - elasticsearch.ssl
  - elasticsearch.config
  - elasticsearch.sostatus

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

{%   if GLOBALS.role != "so-searchnode" %}
escomponenttemplates:
  file.recurse:
    - name: /opt/so/conf/elasticsearch/templates/component
    - source: salt://elasticsearch/templates/component
    - user: 930
    - group: 939
    - clean: True
    - onchanges_in:
      - file: so-elasticsearch-templates-reload
    - show_changes: False

# Clean up legacy and non-SO managed templates from the elasticsearch/templates/index/ directory
so_index_template_dir:
  file.directory:
    - name: /opt/so/conf/elasticsearch/templates/index
    - clean: True
    {%- if SO_MANAGED_INDICES %}
    - require:
      {%- for index in SO_MANAGED_INDICES %}
      - file: so_index_template_{{index}}
      {%- endfor %}
    {%- endif %}

# Auto-generate index templates for SO managed indices (directly defined in elasticsearch/defaults.yaml)
#   These index templates are for the core SO datasets and are always required
{%     for index, settings in ES_INDEX_SETTINGS.items() %}
{%       if settings.index_template is defined %}
so_index_template_{{index}}:
  file.managed:
    - name: /opt/so/conf/elasticsearch/templates/index/{{ index }}-template.json
    - source: salt://elasticsearch/base-template.json.jinja
    - defaults:
        TEMPLATE_CONFIG: {{ settings.index_template }}
    - template: jinja
    - show_changes: False
    - onchanges_in:
      - file: so-elasticsearch-templates-reload
{%       endif %}
{%     endfor %}

# Auto-generate optional index templates for integration | input | content packages
#   These index templates are not used by default (until user adds package to an agent policy).
#   Pre-configured with standard defaults, and incorporated into SOC configuration for user customization.
{%     for index,settings in ALL_ADDON_SETTINGS.items() %}
{%       if settings.index_template is defined %}
addon_index_template_{{index}}:
  file.managed:
    - name: /opt/so/conf/elasticsearch/templates/addon-index/{{ index }}-template.json
    - source: salt://elasticsearch/base-template.json.jinja
    - defaults:
        TEMPLATE_CONFIG: {{ settings.index_template }}
    - template: jinja
    - show_changes: False
    - onchanges_in:
      - file: addon-elasticsearch-templates-reload
{%       endif %}
{%     endfor %}

{%     if GLOBALS.role in GLOBALS.manager_roles %}
so-es-cluster-settings:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-cluster-settings
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: elasticsearch_sbin_jinja
{%     endif %}

so-elasticsearch-ilm-policy-load:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-ilm-policy-load
    - cwd: /opt/so
    - require:
      - docker_container: so-elasticsearch
      - file: so-elasticsearch-ilm-policy-load-script
    - onchanges:
      - file: so-elasticsearch-ilm-policy-load-script

so-elasticsearch-templates-reload:
  file.absent:
    - name: /opt/so/state/estemplates.txt

addon-elasticsearch-templates-reload:
  file.absent:
    - name: /opt/so/state/addon_estemplates.txt

so-elasticsearch-templates:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-templates-load
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: elasticsearch_sbin_jinja

so-elasticsearch-pipelines:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-pipelines {{ GLOBALS.hostname }}
    - require:
      - docker_container: so-elasticsearch
      - file: so-elasticsearch-pipelines-script

so-elasticsearch-roles-load:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-roles-load
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: elasticsearch_sbin_jinja

{%     if grains.role in ['so-managersearch', 'so-manager', 'so-managerhype'] %}
{%       set ap = "absent" %}
{%     endif %}
{%     if grains.role in ['so-eval', 'so-standalone', 'so-heavynode'] %}
{%       if ELASTICSEARCHMERGED.index_clean %}
{%         set ap = "present" %}
{%       else %}
{%         set ap = "absent" %}
{%       endif %}
{%     endif %}  
{%     if grains.role in ['so-eval', 'so-standalone', 'so-managersearch', 'so-heavynode', 'so-manager'] %}
so-elasticsearch-indices-delete:
  cron.{{ap}}:
    - name: /usr/sbin/so-elasticsearch-indices-delete > /opt/so/log/elasticsearch/cron-elasticsearch-indices-delete.log 2>&1
    - identifier: so-elasticsearch-indices-delete
    - user: root
    - minute: '*/5'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'
{%     endif %}

{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
