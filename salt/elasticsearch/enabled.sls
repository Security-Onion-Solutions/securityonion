# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'logstash/map.jinja' import LOGSTASH_NODES %}
{%   from 'elasticsearch/config.map.jinja' import ES_LOGSTASH_NODES %}
{%   from 'elasticsearch/config.map.jinja' import ELASTICSEARCHMERGED %}
{%   set TEMPLATES = salt['pillar.get']('elasticsearch:templates', {}) %}
{%   from 'elasticsearch/template.map.jinja' import ES_INDEX_SETTINGS %}

include:
  - elasticsearch.config
  - elasticsearch.sostatus

so-elasticsearch:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-elasticsearch:{{ GLOBALS.so_version }}
    - hostname: elasticsearch
    - name: so-elasticsearch
    - user: elasticsearch
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-elasticsearch'].ip }}
    - extra_hosts:
    {% for node in LOGSTASH_NODES %}
    {%   for hostname, ip in node.items() %}
      - {{hostname}}:{{ip}}
    {%   endfor %}
    {% endfor %}
    {% if DOCKER.containers['so-elasticsearch'].extra_hosts %}
      {% for XTRAHOST in DOCKER.containers['so-elasticsearch'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    - environment:
      {% if ES_LOGSTASH_NODES | length == 1 or GLOBALS.role == 'so-heavynode' %}
      - discovery.type=single-node
      {% endif %}
      - ES_JAVA_OPTS=-Xms{{ GLOBALS.elasticsearch.es_heap }} -Xmx{{ GLOBALS.elasticsearch.es_heap }} -Des.transport.cname_in_publish_address=true -Dlog4j2.formatMsgNoLookups=true
      ulimits:
      - memlock=-1:-1
      - nofile=65536:65536
      - nproc=4096
      {% if DOCKER.containers['so-elasticsearch'].extra_env %}
        {% for XTRAENV in DOCKER.containers['so-elasticsearch'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-elasticsearch'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - binds:
      - /opt/so/conf/elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro
      - /opt/so/conf/elasticsearch/log4j2.properties:/usr/share/elasticsearch/config/log4j2.properties:ro
      - /nsm/elasticsearch:/usr/share/elasticsearch/data:rw
      - /opt/so/log/elasticsearch:/var/log/elasticsearch:rw
      - /opt/so/conf/ca/cacerts:/usr/share/elasticsearch/jdk/lib/security/cacerts:ro
      {% if GLOBALS.is_manager %}
      - /etc/pki/ca.crt:/usr/share/elasticsearch/config/ca.crt:ro
      {% else %}
      - /etc/pki/tls/certs/intca.crt:/usr/share/elasticsearch/config/ca.crt:ro
      {% endif %}
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
      {% if DOCKER.containers['so-elasticsearch'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-elasticsearch'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - watch:
      - file: cacertz
      - file: esyml
    - require:
      - file: esyml
      - file: eslog4jfile
      - file: nsmesdir
      - file: eslogdir
      - file: cacertz
      - x509: /etc/pki/elasticsearch.crt
      - x509: /etc/pki/elasticsearch.key
      - file: elasticp12perms
      {% if GLOBALS.is_manager %}
      - x509: pki_public_ca_crt
      {% else %}
      - x509: trusttheca
      {% endif %}
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
      
# Auto-generate templates from defaults file
{%     for index, settings in ES_INDEX_SETTINGS.items() %}
 {%      if settings.index_template is defined %}
es_index_template_{{index}}:
  file.managed:
    - name: /opt/so/conf/elasticsearch/templates/index/{{ index }}-template.json
    - source: salt://elasticsearch/base-template.json.jinja
    - defaults:
      TEMPLATE_CONFIG: {{ settings.index_template }}
    - template: jinja
    - onchanges_in:
      - file: so-elasticsearch-templates-reload
{%       endif %}
{%     endfor %}

{%     if TEMPLATES %}
# Sync custom templates to /opt/so/conf/elasticsearch/templates
{%       for TEMPLATE in TEMPLATES %}
es_template_{{TEMPLATE.split('.')[0] | replace("/","_") }}:
  file.managed:
    - source: salt://elasticsearch/templates/index/{{TEMPLATE}}
{%         if 'jinja' in TEMPLATE.split('.')[-1] %}
    - name: /opt/so/conf/elasticsearch/templates/index/{{TEMPLATE.split('/')[1] | replace(".jinja", "")}}
    - template: jinja
{%         else %}
    - name: /opt/so/conf/elasticsearch/templates/index/{{TEMPLATE.split('/')[1]}}
{%         endif %}
    - user: 930
    - group: 939
    - onchanges_in:
      - file: so-elasticsearch-templates-reload
{%       endfor %}
{%     endif %}

{% if GLOBALS.role in GLOBALS.manager_roles %}
so-es-cluster-settings:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-cluster-settings
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: elasticsearch_sbin_jinja
{% endif %}

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
{% if grains.role in ['so-eval', 'so-standalone', 'so-managersearch', 'so-heavynode', 'so-manager'] %}
so-elasticsearch-indices-delete:
  cron.present:
    - name: /usr/sbin/so-elasticsearch-indices-delete > /opt/so/log/elasticsearch/cron-elasticsearch-indices-delete.log 2>&1
    - identifier: so-elasticsearch-indices-delete
    - user: root
    - minute: '*/5'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'
{% endif %}
{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
