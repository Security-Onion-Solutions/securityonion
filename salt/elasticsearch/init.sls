# Copyright 2014,2015,2016,2017,2018,2019,2020 Security Onion Solutions, LLC

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

{% if grains['role'] == 'so-master' %}

{% set esclustername = salt['pillar.get']('master:esclustername', '') %}
{% set esheap = salt['pillar.get']('master:esheap', '') %}

{% elif grains['role'] in ['so-eval','so-mastersearch'] %}

{% set esclustername = salt['pillar.get']('master:esclustername', '') %}
{% set esheap = salt['pillar.get']('master:esheap', '') %}

{% elif grains['role'] == 'so-node' or grains['role'] == 'so-heavynode' %}

{% set esclustername = salt['pillar.get']('node:esclustername', '') %}
{% set esheap = salt['pillar.get']('node:esheap', '') %}

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

so-elasticsearch:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-elasticsearch:{{ VERSION }}{{ FEATURES }}
    - hostname: elasticsearch
    - name: so-elasticsearch
    - user: elasticsearch
    - environment:
      - discovery.type=single-node
      #- bootstrap.memory_lock=true
      #- cluster.name={{ esclustername }}
      - ES_JAVA_OPTS=-Xms{{ esheap }} -Xmx{{ esheap }}
      #- http.host=0.0.0.0
      #- transport.host=127.0.0.1
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

{% if grains['role'] == 'so-master' or grains['role'] == "so-eval" or grains['role'] == "so-mastersearch" %}
so-elasticsearch-templates:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-templates
    - cwd: /opt/so
{% endif %}