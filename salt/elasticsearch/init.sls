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
{% if grains['role'] == 'so-master' %}

{% set esclustername = salt['pillar.get']('master:esclustername', '') %}
{% set esheap = salt['pillar.get']('master:esheap', '') %}
{% set freq = salt['pillar.get']('master:freq', '0') %}
{% set dstats = salt['pillar.get']('master:dstats', '0') %}

{% elif grains['role'] == 'so-eval' %}

{% set esclustername = salt['pillar.get']('master:esclustername', '') %}
{% set esheap = salt['pillar.get']('master:esheap', '') %}
{% set freq = salt['pillar.get']('master:freq', '0') %}
{% set dstats = salt['pillar.get']('master:dstats', '0') %}

{% elif grains['role'] == 'so-node' %}

{% set esclustername = salt['pillar.get']('node:esclustername', '') %}
{% set esheap = salt['pillar.get']('node:esheap', '') %}
{% set freq = salt['pillar.get']('node:freq', '0') %}
{% set dstats = salt['pillar.get']('node:dstats', '0') %}

{% endif %}

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

esingestdir:
  file.directory:
    - name: /opt/so/conf/elasticsearch/ingest
    - user: 930
    - group: 939
    - makedirs: True

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

so-elasticsearchimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-elasticsearch:HH1.1.0

so-elasticsearch:
  docker_container.running:
    - require:
      - so-elasticsearchimage
    - image: docker.io/soshybridhunter/so-elasticsearch:HH1.1.0
    - hostname: elasticsearch
    - name: so-elasticsearch
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
      - 0.0.0.0:9200:9200
      - 0.0.0.0:9300:9300
    - binds:
      - /opt/so/conf/elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro
      - /opt/so/conf/elasticsearch/log4j2.properties:/usr/share/elasticsearch/config/log4j2.properties:ro
      - /nsm/elasticsearch:/usr/share/elasticsearch/data:rw
      - /opt/so/log/elasticsearch:/var/log/elasticsearch:rw

so-elasticsearch-pipelines-file:
  file.managed:
    - name: /opt/so/conf/elasticsearch/so-elasticsearch-pipelines
    - source: salt://elasticsearch/files/so-elasticsearch-pipelines
    - user: 930
    - group: 939
    - mode: 754

so-elasticsearch-pipelines:
 cmd.run:
   - name: /opt/so/conf/elasticsearch/so-elasticsearch-pipelines {{ esclustername }}

# Tell the main cluster I am here
#curl -XPUT http://\$ELASTICSEARCH_HOST:\$ELASTICSEARCH_PORT/_cluster/settings -H'Content-Type: application/json' -d '{"persistent": {"search": {"remote": {"$HOSTNAME": {"skip_unavailable": "true", "seeds": ["$DOCKER_INTERFACE:$REVERSE_PORT"]}}}}}'

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

so-freqimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-freqserver:HH1.0.3

so-freq:
  docker_container.running:
    - require:
      - so-freqimage
    - image: docker.io/soshybridhunter/so-freqserver:HH1.0.3
    - hostname: freqserver
    - name: so-freqserver
    - user: freqserver
    - binds:
      - /opt/so/log/freq_server:/var/log/freq_server:rw


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

so-domainstatsimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-domainstats:HH1.0.3

so-domainstats:
  docker_container.running:
    - require:
      - so-domainstatsimage
    - image: docker.io/soshybridhunter/so-domainstats:HH1.0.3
    - hostname: domainstats
    - name: so-domainstats
    - user: domainstats
    - binds:
      - /opt/so/log/domainstats:/var/log/domain_stats


{% endif %}
