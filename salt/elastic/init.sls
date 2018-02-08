# ES
so-elasticsearch:
  dockerng.running:
    - image: pillaritem/so-logstash
    - hostname: elasticsearch
    - user:
    - environment:
      - "bootstrap.memory_lock=true"
      - "cluster.name={{ grains.host }}"
      - ES_JAVA_OPTS="-Xms$ELASTICSEARCH_HEAP -Xmx$ELASTICSEARCH_HEAP"
      - "http.host=0.0.0.0"
      - "transport.host=127.0.0.1" 
    - port_bindings:
      - 9200
      - 9300
    - binds:
      - /opt/so/conf/logstash/log4j2.properties:/usr/share/logstash/config/log4j2.properties:ro
      - /etc/elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro
      - /etc/elasticsearch/log4j2.properties:/usr/share/elasticsearch/config/log4j2.properties:ro
      - /nsm/elasticsearch:/usr/share/elasticsearch/data
      - /var/log/elasticsearch:/var/log/elasticsearch
    - network_mode: so-elastic-net















                        --ulimit memlock=-1:-1 \
                        --ulimit nofile=65536:65536 \
                        --ulimit nproc=4096 \
                        $ELASTICSEARCH_OPTIONS \
