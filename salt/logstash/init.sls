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
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.1.4') %}
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

# Create a directory for people to drop their own custom parsers into
lscustdir:
  file.directory:
    - name: /opt/so/conf/logstash/custom
    - user: 931
    - group: 939
    - makedirs: True

lsdyndir:
  file.directory:
    - name: /opt/so/conf/logstash/dynamic
    - user: 931
    - group: 939
    - makedirs: True

lsetcdir:
  file.directory:
    - name: /opt/so/conf/logstash/etc
    - user: 931
    - group: 939
    - makedirs: True

lscustparserdir:
  file.directory:
    - name: /opt/so/conf/logstash/custom/parsers
    - user: 931
    - group: 939
    - makedirs: True

lscusttemplatedir:
  file.directory:
    - name: /opt/so/conf/logstash/custom/templates
    - user: 931
    - group: 939
    - makedirs: True

{% for PL in PIPELINES %}
ls_pipeline_{{PL}}:
  file.directory:
    - name: /opt/so/conf/logstash/pipelines/{{PL}}
    - user: 931
    - group: 939

  {% for CONFIGFILE in PIPELINES[PL].config %}
ls_pipeline_{{PL}}_{{CONFIGFILE.split('.')[0]}}:
  file.managed:
    - source: salt://logstash/pipelines/config/{{CONFIGFILE}}
    {% if 'jinja' in CONFIGFILE.split('.')[-1] %}
    - name: /opt/so/conf/logstash/pipelines/{{PL}}/{{CONFIGFILE | replace(".jinja", "")}}
    - template: jinja
    {% else %}
    - name: /opt/so/conf/logstash/pipelines/{{PL}}/{{CONFIGFILE}}
    {% endif %}
    - user: 931
    - group: 939
  {% endfor %}
{% endfor %}

lspipelinesyml:
  file.managed:
    - name: /opt/so/conf/logstash/etc/pipelines.yml
    - source: salt://logstash/etc/pipelines.yml.jinja
    - template: jinja
    - defaults:
        pipelines: {{ PIPELINES }}

# Copy down all the configs including custom - TODO add watch restart
lsetcsync:
  file.recurse:
    - name: /opt/so/conf/logstash/etc
    - source: salt://logstash/etc
    - user: 931
    - group: 939
    - template: jinja
    - exclude_pat: pipelines*

lssync:
  file.recurse:
    - name: /opt/so/conf/logstash/dynamic
    - source: salt://logstash/files/dynamic
    - user: 931
    - group: 939
    - template: jinja

lscustsync:
  file.recurse:
    - name: /opt/so/conf/logstash/custom
    - source: salt://logstash/files/custom
    - user: 931
    - group: 939

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
      - 0.0.0.0:514:514
      - 0.0.0.0:5044:5044
      - 0.0.0.0:5644:5644
      - 0.0.0.0:6050:6050
      - 0.0.0.0:6051:6051
      - 0.0.0.0:6052:6052
      - 0.0.0.0:6053:6053
      - 0.0.0.0:9600:9600
    - binds:
      - /opt/so/conf/logstash/etc/log4j2.properties:/usr/share/logstash/config/log4j2.properties:ro
      - /opt/so/conf/logstash/etc/logstash.yml:/usr/share/logstash/config/logstash.yml:ro
      - /opt/so/conf/logstash/etc/logstash-template.json:/logstash-template.json:ro
      - /opt/so/conf/logstash/etc/logstash-ossec-template.json:/logstash-ossec-template.json:ro
      - /opt/so/conf/logstash/etc/logstash-strelka-template.json:/logstash-strelka-template.json:ro
      - /opt/so/conf/logstash/etc/beats-template.json:/beats-template.json:ro
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
      - file: /opt/so/conf/logstash/etc
      - file: /opt/so/conf/logstash/custom
      #- file: /opt/so/conf/logstash/rulesets
      - file: /opt/so/conf/logstash/dynamic
