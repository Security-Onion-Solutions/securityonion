{% set esclustername = salt['pillar.get'](master:esclustername) %}
{% set esheap = salt['pillar.get'](master:esheap) %}
{% set esaccessip = salt['pillar.get'](master:esaccessip) %}

so-elasticsearch:
  dockerng.running:
    - image: pillaritem/so-logstash
    - hostname: elasticsearch
    - user: elasticsearch
    - environment:
      - bootstrap.memory_lock=true
      - cluster.name={{ esclustername }}
      - ES_JAVA_OPTS="-Xms{{ esheap }} -Xmx{{ esheap }}"
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
      - /opt/so/conf/logstash/log4j2.properties:/usr/share/logstash/config/log4j2.properties:ro
      - /opt/so/conf/elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro
      - /opt/so/conf/elasticsearch/log4j2.properties:/usr/share/elasticsearch/config/log4j2.properties:ro
      - /nsm/elasticsearch:/usr/share/elasticsearch/data:rw
      - /opt/so/log/elasticsearch:/var/log/elasticsearch:rw
    - network_mode: so-elastic-net
