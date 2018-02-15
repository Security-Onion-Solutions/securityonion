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

{% else %}

{% set lsheap = salt['pillar.get']('master:lsheap', '') %}
{% set lsaccessip = salt['pillar.get']('master:lsaccessip', '') %}
{% set freq = salt['pillar.get']('master:freq', '0') %}
{% set dstats = salt['pillar.get']('master:dstats', '0') %}

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
    - name: /opt/so/conf/logstash/pipeline
    - user: 931
    - group: 939
    - makedirs: True

# Copy down all the configs including custom - TODO add watch restart
lssync:
  file.recurse:
    - name: /opt/so/conf/logstash
    - source: salt://logstash/files
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

{% if freq == '0' and dstats == '0' %}

/opt/so/conf/logstash/rulesets.txt:
  file.managed:
    - contents:
      - FREQ=0
      - DSTATS=0

removefreq:
  file.absent:
    - name: /opt/so/conf/logstash/pipeline/*_postprocess_freq_analysis_*.conf

removedstats1:
  file.absent:
    - name: /opt/so/conf/logstash/pipeline/8007_postprocess_dns_top1m_tagging.conf

removedstats2:
  file.absent:
    - name: /opt/so/conf/logstash/pipeline/8008_postprocess_dns_whois_age.conf

{% elif freq == '1' and dstats == '0' %}
/opt/so/conf/logstash/rulesets.txt:
  file.managed:
    - contents:
      - FREQ=1
      - DSTATS=0

removedstats1:
  file.absent:
    - name: /opt/so/conf/logstash/pipeline/8007_postprocess_dns_top1m_tagging.conf
removedstats2:
  file.absent:
    - name: /opt/so/conf/logstash/pipeline/8008_postprocess_dns_whois_age.conf

{% elif freq == '1' and dstats == '1' %}
/opt/so/conf/logstash/rulesets.txt:
  file.managed:
    - contents:
      - FREQ=1
      - DSTATS=1

{% elif freq == '0' and dstats == '1' %}
/opt/so/conf/logstash/rulesets.txt:
  file.managed:
    - contents:
      - FREQ=0
      - DSTATS=1

removefreq:
  file.absent:
    - name: /opt/so/conf/logstash/pipeline/*_postprocess_freq_analysis_*.conf

{% endif %}

# Add the container

so-logstash:
  docker_container.running:
    - image: toosmooth/so-logstash:test2
    - hostname: logstash
    - name: logstash
    - user: logstash
    - environment:
      - LS_JAVA_OPTS=-Xms{{ lsheap }} -Xmx{{ lsheap }}
    - port_bindings:
      - {{ lsaccessip }}:5044:5044
      - {{ lsaccessip }}:6050:6050
      - {{ lsaccessip }}:6051:6051
      - {{ lsaccessip }}:6052:6052
      - {{ lsaccessip }}:6053:6053
      - {{ lsaccessip }}:9600:9600
    - binds:
      - /opt/so/conf/logstash/log4j2.properties:/usr/share/logstash/config/log4j2.properties:ro
      - /opt/so/conf/logstash/logstash.yml:/usr/share/logstash/config/logstash.yml:ro
      - /opt/so/conf/logstash/logstash-template.json:/logstash-template.json:ro
      - /opt/so/conf/logstash/beats-template.json:/beats-template.json:ro
      - /opt/so/conf/logstash/pipeline:/usr/share/logstash/pipeline:rw
      - /opt/so/conf/logstash/rulesets.txt:/usr/share/logstash/rulesets:ro
      - /opt/so/rules:/etc/nsm/rules:ro
      - /nsm/import:/nsm/import:ro
      - /nsm/logstash:/usr/share/logstash/data:rw
      - /opt/so/log/logstash:/var/log/logstash:rw
    - network_mode: so-elastic-net
