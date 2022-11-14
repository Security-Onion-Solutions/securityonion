# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

include:
  - ssl

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'docker/docker.map.jinja' import DOCKER %}
{% set TEMPLATES = salt['pillar.get']('elasticsearch:templates', {}) %}
{% set ROLES = salt['pillar.get']('elasticsearch:roles', {}) %}
{% from 'elasticsearch/config.map.jinja' import ESCONFIG with context %}
{% from 'elasticsearch/template.map.jinja' import ES_INDEX_SETTINGS without context %}
{% from 'logstash/map.jinja' import REDIS_NODES with context %}

vm.max_map_count:
  sysctl.present:
    - value: 262144

{% if GLOBALS.is_manager %}
# We have to add the Manager CA to the CA list
cascriptsync:
  file.managed:
    - name: /usr/sbin/so-catrust
    - source: salt://elasticsearch/tools/sbin/so-catrust
    - user: 939
    - group: 939
    - mode: 750
    - template: jinja
    - defaults:
        GLOBALS: {{ GLOBALS }}

# Run the CA magic
cascriptfun:
  cmd.run:
    - name: /usr/sbin/so-catrust
    - require:
        - file: cascriptsync
{% endif %}

# Sync some es scripts
es_sync_scripts:
  file.recurse:
    - name: /usr/sbin
    - user: root
    - group: root
    - file_mode: 755
    - template: jinja
    - source: salt://elasticsearch/tools/sbin
    - exclude_pat:
        - so-elasticsearch-pipelines # exclude this because we need to watch it for changes, we sync it in another state
    - defaults:
        GLOBALS: {{ GLOBALS }}

so-elasticsearch-pipelines-script:
  file.managed:
    - name: /usr/sbin/so-elasticsearch-pipelines
    - source: salt://elasticsearch/tools/sbin/so-elasticsearch-pipelines
    - user: 930
    - group: 939
    - mode: 754

# Move our new CA over so Elastic and Logstash can use SSL with the internal CA
catrustdir:
  file.directory:
    - name: /opt/so/conf/ca
    - user: 939
    - group: 939
    - makedirs: True

cacertz:
  file.managed:
    - name: /opt/so/conf/ca/cacerts
    - source: salt://common/cacerts
    - user: 939
    - group: 939

capemz:
  file.managed:
    - name: /opt/so/conf/ca/tls-ca-bundle.pem
    - source: salt://common/tls-ca-bundle.pem
    - user: 939
    - group: 939



# Add ES Group
elasticsearchgroup:
  group.present:
    - name: elasticsearch
    - gid: 930

# Add ES user
elasticsearch:
  user.present:
    - uid: 930
    - gid: 930
    - home: /opt/so/conf/elasticsearch
    - createhome: False

esconfdir:
  file.directory:
    - name: /opt/so/conf/elasticsearch
    - user: 930
    - group: 939
    - makedirs: True

esingestdir:
  file.directory:
    - name: /opt/so/conf/elasticsearch/ingest
    - user: 930
    - group: 939
    - makedirs: True

estemplatedir:
  file.directory:
    - name: /opt/so/conf/elasticsearch/templates/index
    - user: 930
    - group: 939
    - makedirs: True

esrolesdir:
  file.directory:
    - name: /opt/so/conf/elasticsearch/roles
    - user: 930
    - group: 939
    - makedirs: True

eslibdir:
  file.absent:
    - name: /opt/so/conf/elasticsearch/lib

esingestdynamicconf:
  file.recurse:
    - name: /opt/so/conf/elasticsearch/ingest
    - source: salt://elasticsearch/files/ingest-dynamic
    - user: 930
    - group: 939
    - template: jinja

esingestconf:
  file.recurse:
    - name: /opt/so/conf/elasticsearch/ingest
    - source: salt://elasticsearch/files/ingest
    - user: 930
    - group: 939

eslog4jfile:
  file.managed:
    - name: /opt/so/conf/elasticsearch/log4j2.properties
    - source: salt://elasticsearch/files/log4j2.properties
    - user: 930
    - group: 939
    - template: jinja

esyml:
  file.managed:
    - name: /opt/so/conf/elasticsearch/elasticsearch.yml
    - source: salt://elasticsearch/files/elasticsearch.yaml.jinja
    - user: 930
    - group: 939
    - defaults:
        ESCONFIG: {{ ESCONFIG }}
    - template: jinja

escomponenttemplates:
  file.recurse:
    - name: /opt/so/conf/elasticsearch/templates/component
    - source: salt://elasticsearch/templates/component
    - user: 930
    - group: 939
    - onchanges_in:
      - cmd: so-elasticsearch-templates
      
# Auto-generate templates from defaults file
{% for index, settings in ES_INDEX_SETTINGS.items() %}
  {% if settings.index_template is defined %}
es_index_template_{{index}}:
  file.managed:
    - name: /opt/so/conf/elasticsearch/templates/index/{{ index }}-template.json
    - source: salt://elasticsearch/base-template.json.jinja
    - defaults:
      TEMPLATE_CONFIG: {{ settings.index_template }}
    - template: jinja
    - onchanges_in:
      - cmd: so-elasticsearch-templates
  {% endif %}
{% endfor %}

{% if TEMPLATES %}
# Sync custom templates to /opt/so/conf/elasticsearch/templates
{% for TEMPLATE in TEMPLATES %}
es_template_{{TEMPLATE.split('.')[0] | replace("/","_") }}:
  file.managed:
    - source: salt://elasticsearch/templates/index/{{TEMPLATE}}
    {% if 'jinja' in TEMPLATE.split('.')[-1] %}
    - name: /opt/so/conf/elasticsearch/templates/index/{{TEMPLATE.split('/')[1] | replace(".jinja", "")}}
    - template: jinja
    {% else %}
    - name: /opt/so/conf/elasticsearch/templates/index/{{TEMPLATE.split('/')[1]}}
    {% endif %}
    - user: 930
    - group: 939
    - onchanges_in:
      - cmd: so-elasticsearch-templates
{% endfor %}
{% endif %}

esroles:
  file.recurse:
    - source: salt://elasticsearch/roles/
    - name: /opt/so/conf/elasticsearch/roles/
    - clean: True
    - template: jinja
    - user: 930
    - group: 939

nsmesdir:
  file.directory:
    - name: /nsm/elasticsearch
    - user: 930
    - group: 939
    - makedirs: True

eslogdir:
  file.directory:
    - name: /opt/so/log/elasticsearch
    - user: 930
    - group: 939
    - makedirs: True

es_repo_dir:
  file.directory:
    - name: /nsm/elasticsearch/repo/
    - user: 930
    - group: 930
    - require:
      - file: nsmesdir

so-pipelines-reload:
  file.absent:
    - name: /opt/so/state/espipelines.txt
    - onchanges:
      - file: esingestconf
      - file: esingestdynamicconf
      - file: esyml
      - file: so-elasticsearch-pipelines-script

auth_users:
  file.managed:
    - name: /opt/so/conf/elasticsearch/users.tmp
    - source: salt://elasticsearch/files/users
    - user: 930
    - group: 930
    - mode: 600
    - show_changes: False

auth_users_roles:
  file.managed:
    - name: /opt/so/conf/elasticsearch/users_roles.tmp
    - source: salt://elasticsearch/files/users_roles
    - user: 930
    - group: 930
    - mode: 600
    - show_changes: False

auth_users_inode:
  require:
    - file: auth_users
  cmd.run:
    - name: cat /opt/so/conf/elasticsearch/users.tmp > /opt/so/conf/elasticsearch/users && chown 930:939 /opt/so/conf/elasticsearch/users && chmod 660 /opt/so/conf/elasticsearch/users
    - onchanges:
      - file: /opt/so/conf/elasticsearch/users.tmp

auth_users_roles_inode:
  require:
    - file: auth_users_roles
  cmd.run:
    - name: cat /opt/so/conf/elasticsearch/users_roles.tmp > /opt/so/conf/elasticsearch/users_roles && chown 930:939 /opt/so/conf/elasticsearch/users_roles && chmod 660 /opt/so/conf/elasticsearch/users_roles
    - onchanges:
      - file: /opt/so/conf/elasticsearch/users_roles.tmp

so-elasticsearch:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-elasticsearch:{{ GLOBALS.so_version }}
    - hostname: elasticsearch
    - name: so-elasticsearch
    - user: elasticsearch
    - ipv4_address: {{ DOCKER.containers['so-elasticsearch'].ip }}
    - extra_hosts:  {{ REDIS_NODES }} 
    - environment:
      {% if REDIS_NODES | length == 1 %}
      - discovery.type=single-node
      {% endif %}
      - ES_JAVA_OPTS=-Xms{{ GLOBALS.elasticsearch.es_heap }} -Xmx{{ GLOBALS.elasticsearch.es_heap }} -Des.transport.cname_in_publish_address=true -Dlog4j2.formatMsgNoLookups=true
      ulimits:
      - memlock=-1:-1
      - nofile=65536:65536
      - nproc=4096
    - port_bindings:
      - 0.0.0.0:9200:9200
      - 0.0.0.0:9300:9300
    - binds:
      - /opt/so/conf/elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro
      - /opt/so/conf/elasticsearch/log4j2.properties:/usr/share/elasticsearch/config/log4j2.properties:ro
      - /nsm/elasticsearch:/usr/share/elasticsearch/data:rw
      - /opt/so/log/elasticsearch:/var/log/elasticsearch:rw
      - /opt/so/conf/ca/cacerts:/usr/share/elasticsearch/jdk/lib/security/cacerts:ro
      {% if GLOBALS.is_manager %}
      - /etc/pki/ca.crt:/usr/share/elasticsearch/config/ca.crt:ro
      {% else %}
      - /etc/ssl/certs/intca.crt:/usr/share/elasticsearch/config/ca.crt:ro
      {% endif %}
      - /etc/pki/elasticsearch.crt:/usr/share/elasticsearch/config/elasticsearch.crt:ro
      - /etc/pki/elasticsearch.key:/usr/share/elasticsearch/config/elasticsearch.key:ro
      - /etc/pki/elasticsearch.p12:/usr/share/elasticsearch/config/elasticsearch.p12:ro
      - /opt/so/conf/elasticsearch/users_roles:/usr/share/elasticsearch/config/users_roles:ro
      - /opt/so/conf/elasticsearch/users:/usr/share/elasticsearch/config/users:ro
      {% if ESCONFIG.path.get('repo', False) %}
        {% for repo in ESCONFIG.path.repo %}
      - {{ repo }}:{{ repo }}:rw
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

append_so-elasticsearch_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-elasticsearch

so-es-cluster-settings:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-cluster-settings
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: es_sync_scripts

so-elasticsearch-templates:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-templates-load
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: es_sync_scripts

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
      - file: es_sync_scripts


{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %} {# if 'elasticsearch' in top_states #}
