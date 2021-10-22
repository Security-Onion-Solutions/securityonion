# Copyright 2014,2015,2016,2017,2018 Security Onion Solutions, LLC

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

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set MANAGERIP = salt['pillar.get']('global:managerip') %}

# Logstash Section - Decide which pillar to use
{% set lsheap = salt['pillar.get']('logstash_settings:lsheap', '') %}
{% if grains['role'] in ['so-eval','so-managersearch', 'so-manager', 'so-standalone'] %}
  {% set freq = salt['pillar.get']('manager:freq', '0') %}
  {% set dstats = salt['pillar.get']('manager:domainstats', '0') %}
  {% set nodetype = salt['grains.get']('role', '')  %}
{% elif grains['role'] == 'so-helix' %}
  {% set freq = salt['pillar.get']('manager:freq', '0') %}
  {% set dstats = salt['pillar.get']('manager:domainstats', '0') %}
  {% set nodetype = salt['grains.get']('role', '')  %}
{% endif %}

{% set PIPELINES = salt['pillar.get']('logstash:pipelines', {}) %}
{% set DOCKER_OPTIONS = salt['pillar.get']('logstash:docker_options', {}) %}
{% set TEMPLATES = salt['pillar.get']('elasticsearch:templates', {}) %}

{% if grains.role in ['so-heavynode'] %}
  {% set EXTRAHOSTHOSTNAME = salt['grains.get']('host') %}
  {% set EXTRAHOSTIP = salt['pillar.get']('sensor:mainip') %}
{% else %}
  {% set EXTRAHOSTHOSTNAME = MANAGER %}
  {% set EXTRAHOSTIP = MANAGERIP %}
{% endif %}

include:
  - ssl
  - elasticsearch

# Create the logstash group
logstashgroup:
  group.present:
    - name: logstash
    - gid: 931

# Add the logstash user for the jog4j settings
logstash:
  user.present:
    - uid: 931
    - gid: 931
    - home: /opt/so/conf/logstash

lsetcdir:
  file.directory:
    - name: /opt/so/conf/logstash/etc
    - user: 931
    - group: 939
    - makedirs: True

lspipelinedir:
  file.directory:
    - name: /opt/so/conf/logstash/pipelines
    - user: 931
    - group: 939

{% for PL in PIPELINES %}
  {% for CONFIGFILE in PIPELINES[PL].config %}
ls_pipeline_{{PL}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}:
  file.managed:
    - source: salt://logstash/pipelines/config/{{CONFIGFILE}}
    {% if 'jinja' in CONFIGFILE.split('.')[-1] %}
    - name: /opt/so/conf/logstash/pipelines/{{PL}}/{{CONFIGFILE.split('/')[1] | replace(".jinja", "")}}
    - template: jinja
    {% else %}
    - name: /opt/so/conf/logstash/pipelines/{{PL}}/{{CONFIGFILE.split('/')[1]}}
    {% endif %}
    - user: 931
    - group: 939
    - mode: 660
    - makedirs: True
  {% endfor %}

ls_pipeline_{{PL}}:
  file.directory:
    - name: /opt/so/conf/logstash/pipelines/{{PL}}
    - user: 931
    - group: 939
    - require:
  {% for CONFIGFILE in PIPELINES[PL].config %}
      - file: ls_pipeline_{{PL}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}
  {% endfor %}
    - clean: True

{% endfor %}

lspipelinesyml:
  file.managed:
    - name: /opt/so/conf/logstash/etc/pipelines.yml
    - source: salt://logstash/etc/pipelines.yml.jinja
    - template: jinja
    - defaults:
        pipelines: {{ PIPELINES }}

# Copy down all the configs
lsetcsync:
  file.recurse:
    - name: /opt/so/conf/logstash/etc
    - source: salt://logstash/etc
    - user: 931
    - group: 939
    - template: jinja
    - clean: True
    - exclude_pat: pipelines*

# Create the import directory
importdir:
  file.directory:
    - name: /nsm/import
    - user: 931
    - group: 939
    - makedirs: True

# Create the logstash data directory
nsmlsdir:
  file.directory:
    - name: /nsm/logstash/tmp
    - user: 931
    - group: 939
    - makedirs: True

# Create the log directory
lslogdir:
  file.directory:
    - name: /opt/so/log/logstash
    - user: 931
    - group: 939
    - makedirs: True

so-logstash:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-logstash:{{ VERSION }}
    - hostname: so-logstash
    - name: so-logstash
    - user: logstash
    - extra_hosts:
      - {{ EXTRAHOSTHOSTNAME }}:{{ EXTRAHOSTIP }}
    - environment:
      - LS_JAVA_OPTS=-Xms{{ lsheap }} -Xmx{{ lsheap }}
    - port_bindings:
{% for BINDING in DOCKER_OPTIONS.port_bindings %}
      - {{ BINDING }}
{% endfor %}
    - binds:
      - /opt/so/conf/elasticsearch/templates/:/templates/:ro
      - /opt/so/conf/logstash/etc/:/usr/share/logstash/config/:ro
      - /opt/so/conf/logstash/pipelines:/usr/share/logstash/pipelines:ro
      - /opt/so/rules:/etc/nsm/rules:ro
      - /nsm/import:/nsm/import:ro
      - /nsm/logstash:/usr/share/logstash/data:rw
      - /opt/so/log/logstash:/var/log/logstash:rw
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
      - /etc/pki/filebeat.crt:/usr/share/logstash/filebeat.crt:ro
      - /etc/pki/filebeat.p8:/usr/share/logstash/filebeat.key:ro
      - /opt/so/conf/logstash/etc/certs:/usr/share/logstash/certs:ro
      {% if grains['role'] == 'so-heavynode' %}
      - /etc/ssl/certs/intca.crt:/usr/share/filebeat/ca.crt:ro
      {% else %}
      - /etc/pki/ca.crt:/usr/share/filebeat/ca.crt:ro
      {% endif %}
      - /opt/so/conf/ca/cacerts:/etc/pki/ca-trust/extracted/java/cacerts:ro
      - /opt/so/conf/ca/tls-ca-bundle.pem:/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem:ro
      {%- if grains['role'] == 'so-eval' %}
      - /nsm/zeek:/nsm/zeek:ro
      - /nsm/suricata:/suricata:ro
      - /nsm/wazuh/logs/alerts:/wazuh/alerts:ro
      - /nsm/wazuh/logs/archives:/wazuh/archives:ro
      - /opt/so/log/fleet/:/osquery/logs:ro
      - /opt/so/log/strelka:/strelka:ro
      {%- endif %}
    - watch:
      - file: lsetcsync
{% for PL in PIPELINES %}
      - file: ls_pipeline_{{PL}}
  {% for CONFIGFILE in PIPELINES[PL].config %}
      - file: ls_pipeline_{{PL}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}
  {% endfor %}
{% endfor %}
{% for TEMPLATE in TEMPLATES %}
      - file: es_template_{{TEMPLATE.split('.')[0] | replace("/","_") }}
{% endfor %}
    - require:
      - x509: filebeat_crt
{% if grains['role'] == 'so-heavynode' %}
      - x509: trusttheca
{% else %}
      - x509: pki_public_ca_crt
{% endif %}
      - file: cacertz
      - file: capemz

append_so-logstash_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-logstash

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
