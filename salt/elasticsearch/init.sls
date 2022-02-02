# Copyright 2014-2022 Security Onion Solutions, LLC

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

include:
  - ssl

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set NODEIP = salt['pillar.get']('elasticsearch:mainip', '') -%}
{% set TRUECLUSTER = salt['pillar.get']('elasticsearch:true_cluster', False) %}
{% set MANAGERIP = salt['pillar.get']('global:managerip') %}

{% if grains['role'] in ['so-eval','so-managersearch', 'so-manager', 'so-standalone', 'so-import'] %}
  {% set esclustername = salt['pillar.get']('manager:esclustername') %}
  {% set esheap = salt['pillar.get']('manager:esheap') %}
  {% set ismanager = True %}
{% elif grains['role'] in ['so-node','so-heavynode'] %}
  {% set esclustername = salt['pillar.get']('elasticsearch:esclustername') %}
  {% set esheap = salt['pillar.get']('elasticsearch:esheap') %}
  {% set ismanager = False %}
{% elif grains['role'] == 'so-helix' %}
  {% set ismanager = True %} {# Solely for the sake of running so-catrust #}
{% endif %}

{% set TEMPLATES = salt['pillar.get']('elasticsearch:templates', {}) %}
{% set ROLES = salt['pillar.get']('elasticsearch:roles', {}) %}
{% from 'elasticsearch/auth.map.jinja' import ELASTICAUTH with context %}
{% from 'elasticsearch/config.map.jinja' import ESCONFIG with context %}


vm.max_map_count:
  sysctl.present:
    - value: 262144

{% if ismanager %}
# We have to add the Manager CA to the CA list
cascriptsync:
  file.managed:
    - name: /usr/sbin/so-catrust
    - source: salt://elasticsearch/tools/sbin/so-catrust
    - user: 939
    - group: 939
    - mode: 750
    - template: jinja

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
    - defaults:
        ELASTICCURL: 'curl'
    - context:
        ELASTICCURL: {{ ELASTICAUTH.elasticcurl }}
    - exclude_pat:
        - so-elasticsearch-pipelines # exclude this because we need to watch it for changes, we sync it in another state

so-elasticsearch-pipelines-script:
  file.managed:
    - name: /usr/sbin/so-elasticsearch-pipelines
    - source: salt://elasticsearch/tools/sbin/so-elasticsearch-pipelines
    - user: 930
    - group: 939
    - mode: 754
    - template: jinja
    - defaults:
        ELASTICCURL: {{ ELASTICAUTH.elasticcurl }}

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

{% if grains['role'] != 'so-helix' %}

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

#sync templates to /opt/so/conf/elasticsearch/templates
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
{% endfor %}

escomponenttemplates:
  file.recurse:
    - name: /opt/so/conf/elasticsearch/templates/component
    - source: salt://elasticsearch/templates/component
    - user: 930
    - group: 939

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
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-elasticsearch:{{ VERSION }}
    - hostname: elasticsearch
    - name: so-elasticsearch
    - user: elasticsearch
    - extra_hosts: 
      {% if ismanager %}
      - {{ grains.host }}:{{ NODEIP }}
        {% if salt['pillar.get']('nodestab', {}) %}
          {% for SN, SNDATA in salt['pillar.get']('nodestab', {}).items() %}
      - {{ SN.split('_')|first }}:{{ SNDATA.ip }}
          {% endfor %}
        {% endif %}
      {% else %}
      - {{ grains.host }}:{{ NODEIP }}
      - {{ MANAGER }}:{{ MANAGERIP }}
      {% endif %}
    - environment:
      {% if TRUECLUSTER is sameas false or (TRUECLUSTER is sameas true and not salt['pillar.get']('nodestab', {})) %}
      - discovery.type=single-node
      {% endif %}
      - ES_JAVA_OPTS=-Xms{{ esheap }} -Xmx{{ esheap }} -Des.transport.cname_in_publish_address=true -Dlog4j2.formatMsgNoLookups=true
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
      {% if ismanager %}
      - /etc/pki/ca.crt:/usr/share/elasticsearch/config/ca.crt:ro
      {% else %}
      - /etc/ssl/certs/intca.crt:/usr/share/elasticsearch/config/ca.crt:ro
      {% endif %}
      - /etc/pki/elasticsearch.crt:/usr/share/elasticsearch/config/elasticsearch.crt:ro
      - /etc/pki/elasticsearch.key:/usr/share/elasticsearch/config/elasticsearch.key:ro
      - /etc/pki/elasticsearch.p12:/usr/share/elasticsearch/config/elasticsearch.p12:ro
      {% if salt['pillar.get']('elasticsearch:auth:enabled', False) %}
      - /opt/so/conf/elasticsearch/users_roles:/usr/share/elasticsearch/config/users_roles:ro
      - /opt/so/conf/elasticsearch/users:/usr/share/elasticsearch/config/users:ro
      {% endif %}
      {% if ESCONFIG.path.get('repo', False) %}
        {% for repo in ESCONFIG.path.repo %}
      - {{ repo }}:{{ repo }}:rw
        {% endfor %}
      {% endif %}
    - watch:
      - file: cacertz
      - file: esyml
      - file: esingestconf
      - file: esingestdynamicconf
      - file: so-elasticsearch-pipelines-script
    - require:
      - file: esyml
      - file: eslog4jfile
      - file: nsmesdir
      - file: eslogdir
      - file: cacertz
      - x509: /etc/pki/elasticsearch.crt
      - x509: /etc/pki/elasticsearch.key
      - file: elasticp12perms
      {% if ismanager %}
      - x509: pki_public_ca_crt
      {% else %}
      - x509: trusttheca
      {% endif %}
      {% if salt['pillar.get']('elasticsearch:auth:enabled', False) %}
      - cmd: auth_users_roles_inode
      - cmd: auth_users_inode
      {% endif %}

append_so-elasticsearch_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-elasticsearch

so-elasticsearch-pipelines:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-pipelines {{ grains.host }}
    - onchanges:
      - file: esingestconf
      - file: esingestdynamicconf
      - file: esyml
      - file: so-elasticsearch-pipelines-script
    - require:
      - docker_container: so-elasticsearch
      - file: so-elasticsearch-pipelines-script

{% if TEMPLATES %}
so-elasticsearch-templates:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-templates-load
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: es_sync_scripts
{% endif %}

so-elasticsearch-roles-load:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-roles-load
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: es_sync_scripts

{% endif %} {# if grains['role'] != 'so-helix' #}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %} {# if 'elasticsearch' in top_states #}
