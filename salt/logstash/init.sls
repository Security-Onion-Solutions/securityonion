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
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}
{% set FEATURES = salt['pillar.get']('elastic:features', False) %}
{% if FEATURES %}
  {% set FEATURES = "-features" %}
{% else %}
  {% set FEATURES = '' %}
{% endif %}

# Logstash Section - Decide which pillar to use
{% if grains['role'] == 'so-sensor' %}

{% set lsheap = salt['pillar.get']('sensor:lsheap', '') %}
{% set lsaccessip = salt['pillar.get']('sensor:lsaccessip', '') %}

{% elif grains['role'] == 'so-node' or grains['role'] == 'so-heavynode' %}
{% set lsheap = salt['pillar.get']('node:lsheap', '') %}
{% set nodetype = salt['pillar.get']('node:node_type', 'storage') %}

{% elif grains['role'] == 'so-master' %}

{% set lsheap = salt['pillar.get']('master:lsheap', '') %}
{% set freq = salt['pillar.get']('master:freq', '0') %}
{% set dstats = salt['pillar.get']('master:domainstats', '0') %}
{% set nodetype = salt['grains.get']('role', '')  %}

{% elif grains['role'] == 'so-helix' %}

{% set lsheap = salt['pillar.get']('master:lsheap', '') %}
{% set freq = salt['pillar.get']('master:freq', '0') %}
{% set dstats = salt['pillar.get']('master:domainstats', '0') %}
{% set nodetype = salt['grains.get']('role', '')  %}

{% elif grains['role'] in ['so-eval','so-mastersearch'] %}

{% set lsheap = salt['pillar.get']('master:lsheap', '') %}
{% set freq = salt['pillar.get']('master:freq', '0') %}
{% set dstats = salt['pillar.get']('master:domainstats', '0') %}
{% set nodetype = salt['grains.get']('role', '')  %}

{% endif %}

{% set PIPELINES = salt['pillar.get']('logstash:pipelines', {}) %}
{% set TEMPLATES = salt['pillar.get']('logstash:templates', {}) %}
{% set DOCKER_OPTIONS = salt['pillar.get']('logstash:docker_options', {}) %}

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

#sync templates to /opt/so/conf/logstash/etc
{% for TEMPLATE in TEMPLATES %}
ls_template_{{TEMPLATE.split('.')[0] | replace("/","_") }}:
  file.managed:
    - source: salt://logstash/pipelines/templates/{{TEMPLATE}}
    {% if 'jinja' in TEMPLATE.split('.')[-1] %}
    - name: /opt/so/conf/logstash/etc/{{TEMPLATE.split('/')[1] | replace(".jinja", "")}}
    - template: jinja
    {% else %}
    - name: /opt/so/conf/logstash/etc/{{TEMPLATE.split('/')[1]}}
    {% endif %}
    - user: 931
    - group: 939
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
{% if TEMPLATES %}
    - require:
  {% for TEMPLATE in TEMPLATES %}
      - file: ls_template_{{TEMPLATE.split('.')[0] | replace("/","_") }}
  {% endfor %}
{% endif %}
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
    - name: /nsm/logstash
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
    - image: {{ MASTER }}:5000/soshybridhunter/so-logstash:{{ VERSION }}{{ FEATURES }}
    - hostname: so-logstash
    - name: so-logstash
    - user: logstash
    - environment:
      - LS_JAVA_OPTS=-Xms{{ lsheap }} -Xmx{{ lsheap }}
    - port_bindings:
{% for BINDING in DOCKER_OPTIONS.port_bindings %}
      - {{ BINDING }}
{% endfor %}
    - binds:
{% for TEMPLATE in TEMPLATES %}
  {% if 'jinja' in TEMPLATE.split('.')[-1] %}
      - /opt/so/conf/logstash/etc/{{TEMPLATE.split('/')[1] | replace(".jinja", "")}}:/{{TEMPLATE.split('/')[1] | replace(".jinja", "")}}:ro
  {% else %}
      - /opt/so/conf/logstash/etc/{{TEMPLATE.split('/')[1]}}:/{{TEMPLATE.split('/')[1]}}:ro
  {% endif %}
{% endfor %}
      - /opt/so/conf/logstash/etc/log4j2.properties:/usr/share/logstash/config/log4j2.properties:ro
      - /opt/so/conf/logstash/etc/logstash.yml:/usr/share/logstash/config/logstash.yml:ro
      - /opt/so/conf/logstash/etc/pipelines.yml:/usr/share/logstash/config/pipelines.yml
      - /opt/so/conf/logstash/pipelines:/usr/share/logstash/pipelines:ro
      - /opt/so/rules:/etc/nsm/rules:ro
      - /nsm/import:/nsm/import:ro
      - /nsm/logstash:/usr/share/logstash/data:rw
      - /opt/so/log/logstash:/var/log/logstash:rw
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
      - /etc/pki/filebeat.crt:/usr/share/logstash/filebeat.crt:ro
      - /etc/pki/filebeat.p8:/usr/share/logstash/filebeat.key:ro
      - /etc/pki/ca.crt:/usr/share/filebeat/ca.crt:ro
      {%- if grains['role'] == 'so-eval' %}
      - /nsm/zeek:/nsm/zeek:ro
      - /opt/so/log/suricata:/suricata:ro
      - /opt/so/wazuh/logs/alerts:/wazuh/alerts:ro
      - /opt/so/wazuh/logs/archives:/wazuh/archives:ro
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
      - file: ls_template_{{TEMPLATE.split('.')[0] | replace("/","_") }}
{% endfor %}
#     - file: /opt/so/conf/logstash/rulesets
