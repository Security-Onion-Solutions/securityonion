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

{% set esclustername = salt['pillar.get']('master:esclustername', '') %}
{% set esheap = salt['pillar.get']('master:esheap', '') %}
{% set esaccessip = salt['pillar.get']('master:esaccessip', '') %}
{% set freq = salt['pillar.get']('master:freq', '0') %}
{% set dstats = salt['pillar.get']('master:dstats', '0') %}
{% set esalert = salt['pillar.get']('master:elastalert', '1') %}

vm.max_map_count:
  sysctl.present:
    - value: 262144

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
    - source: salt://elasticsearch/files/elasticsearch.yml
    - user: 930
    - group: 939
    - template: jinja

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

so-elasticsearch:
  docker_container.running:
    - image: securityonionsolutions/so-elasticsearch:latest
    - hostname: elasticsearch
    - name: elasticsearch
    - user: elasticsearch
    - environment:
      - bootstrap.memory_lock=true
      - cluster.name={{ esclustername }}
      - ES_JAVA_OPTS=-Xms{{ esheap }} -Xmx{{ esheap }}
      - http.host=0.0.0.0
      - transport.host=127.0.0.1
    - ulimits:
      - memlock=-1:-1
      - nofile=65536:65536
      - nproc=4096
    - port_bindings:
      - {{ esaccessip }}:9200:9200
      - {{ esaccessip }}:9300:9300
    - binds:
      - /opt/so/conf/elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro
      - /opt/so/conf/elasticsearch/log4j2.properties:/usr/share/elasticsearch/config/log4j2.properties:ro
      - /nsm/elasticsearch:/usr/share/elasticsearch/data:rw
      - /opt/so/log/elasticsearch:/var/log/elasticsearch:rw
    - network_mode: so-elastic-net

# See if Freqserver is enabled
{% if freq == 1 %}

# Create the user
fservergroup:
  group.present:
    - name: freqserver
    - gid: 935

# Add ES user
freqserver:
  user.present:
    - uid: 935
    - gid: 935
    - home: /opt/so/conf/freqserver
    - createhome: False

# Create the log directory
freqlogdir:
  file.directory:
    - name: /opt/so/log/freq_server
    - user: 935
    - group: 935
    - makedirs: True

so-freq:
  docker_container.running:
    - image: securityonionsolutions/so-freqserver
    - hostname: freqserver
    - user: freqserver
    - binds:
      - /opt/so/log/freq_server:/var/log/freq_server:rw
    - network_mode: so-elastic-net

{% endif %}

{% if dstats == 1 %}

# Create the group
dstatsgroup:
  group.present:
    - name: domainstats
    - gid: 936

# Add user
domainstats:
  user.present:
    - uid: 936
    - gid: 936
    - home: /opt/so/conf/domainstats
    - createhome: False

# Create the log directory
dstatslogdir:
  file.directory:
    - name: /opt/so/log/domainstats
    - user: 936
    - group: 939
    - makedirs: True

so-domainstats:
  docker_container.running:
    - image: securityonionsolutions/so-domainstats
    - hostname: domainstats
    - name: domainstats
    - user: domainstats
    - binds:
      - /opt/so/log/domainstats:/var/log/domain_stats
    - network_mode: so-elastic-net

{% endif %}

# Curator
# Create the group
curatorgroup:
  group.present:
    - name: curator
    - gid: 934

# Add user
curator:
  user.present:
    - uid: 934
    - gid: 934
    - home: /opt/so/conf/curator
    - createhome: False

# Create the log directory
curactiondir:
  file.directory:
    - name: /opt/so/conf/curator/action
    - user: 934
    - group: 939
    - makedirs: True

curlogdir:
  file.directory:
    - name: /opt/so/log/curator
    - user: 934
    - group: 939

curclose:
  file.managed:
    - name: /opt/so/conf/curator/action/close.yml
    - source: salt://elasticsearch/files/curator/action/close.yml
    - user: 934
    - group: 939
    - template: jinja

curdel:
  file.managed:
    - name: /opt/so/conf/curator/action/delete.yml
    - source: salt://elasticsearch/files/curator/action/delete.yml
    - user: 934
    - group: 939
    - template: jinja

curconf:
  file.managed:
    - name: /opt/so/conf/curator/curator.yml
    - source: salt://elasticsearch/files/curator/curator.yml
    - user: 934
    - group: 939
    - template: jinja

so-curator:
  docker_container.running:
    - image: securityonionsolutions/so-curator
    - hostname: curator
    - name: curator
    - user: curator
    - interactive: True
    - tty: True
    - binds:
      - /opt/so/conf/curator/curator.yml:/etc/curator/config/curator.yml:ro
      - /opt/so/conf/curator/action/:/etc/curator/action:ro
      - /opt/so/log/curator:/var/log/curator
    - network_mode: so-elastic-net

# Elastalert
{% if esalert == 1 %}

# Create the group
elastagroup:
  group.present:
    - name: curator
    - gid: 934

# Add user
elastalert:
  user.present:
    - uid: 934
    - gid: 934
    - home: /opt/so/conf/elastalert
    - createhome: False

elastalogdir:
  file.directory:
    - name: /opt/so/log/elastalert
    - user: 934
    - group: 939
    - makedirs: True

elastarules:
  file.directory:
    - name: /opt/so/rules/elastalert
    - user: 934
    - group: 939
    - makedirs: True

elastaconf:
  file.directory:
    - name: /opt/so/conf/elastalert
    - user: 934
    - group: 939
    - makedirs: True

so-elastalert:
  docker_container.running:
    - image: securityonionsolutions/so-elastalert
    - hostname: elastalert
    - name: elastalert
    - user: elastalert
    - detach: True
    - binds:
      - /etc/elastalert/rules/:/etc/elastalert/rules/
      - /opt/so/log/elastalert:/var/log/elastalert
    - network_mode: so-elastic-net

{% endif %}
