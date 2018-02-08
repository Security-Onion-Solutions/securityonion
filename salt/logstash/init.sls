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

# Logstash Section

# Only run this is you are in the sensor role
{% if grains['role'] == 'so-sensor' %}

# Add Logstash user
logstash:
  user.present:
    - uid: 931
    - gid: 931
    - home: /opt/so/conf/logstash

# Create logstash conf directory
file.directory:
  - name: /opt/so/conf/logstash
  - user: 931
  - group: 939
  - makedirs: True

# Set the heap size from the sensor pillar
{% set lsheap = salt['pillar.get'](sensor:lsheap) %}

{% else %}

# Set the heap size from the master pillar
{% set lsheap = salt['pillar.get'](master:lsheap) %}

{% endif %}

# Create the conf/d logstash directory
file.directory:
  - name: /opt/so/conf/logstash/conf.d
  - user: 931
  - group: 939

# Copy down all the configs
file.recurse:
  - name: /opt/so/conf/logstash
  - source: salt://sensor/files/logstash
  - user: 931
  - group: 939

# Create the import directory
file.directory:
  - name: /nsm/import
  - user: 931
  - group: 939

# Create the logstash data directory
file.directory:
  - name: /nsm/logstash
  - user: 931
  - group: 939

# Create the log directory
file.directory:
  - name: /opt/so/log/logstash
  - user: 931
  - group: 939


# Add the container

so-logstash:
  dockerng.running:
    - image: pillaritem/so-logstash
    - hostname: logstash
    - user: logstash
    - environment:
      - LS_JAVA_OPTS="-Xms{{ lsheap }} -Xmx{{ lsheap }}"
    - ports:
      - 5044
      - 6050
      - 6051
      - 6052
      - 6053
      - 9600
    - binds:
      - /opt/so/conf/logstash/log4j2.properties:/usr/share/logstash/config/log4j2.properties:ro
      - /opt/so/conf/logstash/logstash.yml:/usr/share/logstash/config/logstash.yml:ro
      - /opt/so/conf/logstash/logstash-template.json:/logstash-template.json:ro
      - /opt/so/conf/logstash/beats-template.json:/beats-template.json:ro
      - /opt/so/conf/logstash/conf.d:/usr/share/logstash/pipeline/:ro
      - /opt/so/rules:/etc/nsm/rules:ro
      - /opt/so/conf/logstash/dictionaries:/lib/dictionaries:ro
      - /nsm/import:/nsm/import:ro
      - /nsm/logstash:/usr/share/logstash/data:rw
      - /opt/so/log/logstash:/var/log/logstash:rw
    - network_mode: so-elastic-net
