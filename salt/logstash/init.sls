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

# Logstash Section - Decide which pillar to use
{% if grains['role'] == 'so-sensor' %}

{% set lsheap = salt['pillar.get']('sensor:lsheap', '') %}
{% set lsaccessip = salt['pillar.get']('sensor:lsaccessip', '') %}

{% elif grains['role'] == 'so-node' %}
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

{% elif grains['role'] == 'so-eval' %}

{% set lsheap = salt['pillar.get']('master:lsheap', '') %}
{% set freq = salt['pillar.get']('master:freq', '0') %}
{% set dstats = salt['pillar.get']('master:domainstats', '0') %}
{% set nodetype = salt['grains.get']('role', '')  %}

{% endif %}

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

# Copy down all the configs including custom - TODO add watch restart
lsetcsync:
  file.recurse:
    - name: /opt/so/conf/logstash/etc
    - source: salt://logstash/etc
    - user: 931
    - group: 939
    - template: jinja

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

# Copy the config file for enabled logstash plugins/parsers
lsconfsync:
  file.managed:
    - name: /opt/so/conf/logstash/conf.enabled.txt
    - source: salt://logstash/conf/conf.enabled.txt.{{ nodetype }}
    - user: 931
    - group: 939
    - template: jinja

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

# Add the container
so-logstashimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-logstash:HH1.1.4

so-logstash:
  docker_container.running:
    - require:
      - so-logstashimage
    - image: docker.io/soshybridhunter/so-logstash:HH1.1.4
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
      - /opt/so/conf/logstash/etc/beats-template.json:/beats-template.json:ro
      - /opt/so/conf/logstash/custom:/usr/share/logstash/pipeline.custom:ro
      - /opt/so/conf/logstash/rulesets:/usr/share/logstash/rulesets:ro
      - /opt/so/conf/logstash/dynamic:/usr/share/logstash/pipeline.dynamic
      - /opt/so/conf/logstash/conf.enabled.txt:/usr/share/logstash/conf.enabled.txt:ro
      - /opt/so/rules:/etc/nsm/rules:ro
      - /nsm/import:/nsm/import:ro
      - /nsm/logstash:/usr/share/logstash/data:rw
      - /opt/so/log/logstash:/var/log/logstash:rw
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
      - /etc/pki/filebeat.crt:/usr/share/logstash/filebeat.crt:ro
      - /etc/pki/filebeat.p8:/usr/share/logstash/filebeat.key:ro
      - /etc/pki/ca.crt:/usr/share/filebeat/ca.crt:ro
      {%- if grains['role'] == 'so-eval' %}
      - /nsm/bro:/nsm/bro:ro
      - /opt/so/log/suricata:/suricata:ro
      {%- endif %}
    - watch:
      - file: /opt/so/conf/logstash/etc
      - file: /opt/so/conf/logstash/conf.enabled.txt
      - file: /opt/so/conf/logstash/custom
      #- file: /opt/so/conf/logstash/rulesets
      - file: /opt/so/conf/logstash/dynamic
