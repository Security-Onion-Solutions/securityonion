{% set MASTERIP = salt['pillar.get']('master:mainip', '') %}
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}
hiveconfdir:
  file.directory:
    - name: /opt/so/conf/hive/etc
    - makedirs: True
    - user: 939
    - group: 939

hivelogdir:
  file.directory:
    - name: /opt/so/log/hive
    - makedirs: True
    - user: 939
    - group: 939

hiveconf:
  file.recurse:
    - name: /opt/so/conf/hive/etc
    - source: salt://hive/thehive/etc
    - user: 939
    - group: 939
    - template: jinja

cortexconfdir:
  file.directory:
    - name: /opt/so/conf/cortex
    - makedirs: True
    - user: 939
    - group: 939

cortexlogdir:
  file.directory:
    - name: /opt/so/log/cortex
    - makedirs: True
    - user: 939
    - group: 939

cortexconf:
  file.recurse:
    - name: /opt/so/conf/cortex
    - source: salt://hive/thehive/etc
    - user: 939
    - group: 939
    - template: jinja

# Install Elasticsearch

# Made directory for ES data to live in
hiveesdata:
  file.directory:
    - name: /nsm/hive/esdata
    - makedirs: True
    - user: 939
    - group: 939

so-thehive-es:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-thehive-es:{{ VERSION }}
    - hostname: so-thehive-es
    - name: so-thehive-es
    - user: 939
    - interactive: True
    - tty: True
    - binds:
      - /nsm/hive/esdata:/usr/share/elasticsearch/data:rw
      - /opt/so/conf/hive/etc/es/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro
      - /opt/so/conf/hive/etc/es/log4j2.properties:/usr/share/elasticsearch/config/log4j2.properties:ro
      - /opt/so/log/hive:/var/log/elasticsearch:rw
    - environment:
      - http.host=0.0.0.0
      - http.port=9400
      - transport.tcp.port=9500
      - transport.host=0.0.0.0
      - cluster.name=hive
      - thread_pool.index.queue_size=100000
      - thread_pool.search.queue_size=100000
      - thread_pool.bulk.queue_size=100000
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
    - port_bindings:
      - 0.0.0.0:9400:9400
      - 0.0.0.0:9500:9500

# Install Cortex
so-cortex:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-thehive-cortex:{{ VERSION }}
    - hostname: so-cortex
    - name: so-cortex
    - user: 939
    - binds:
      - /opt/so/conf/hive/etc/cortex-application.conf:/opt/cortex/conf/application.conf:ro
    - port_bindings:
      - 0.0.0.0:9001:9001

cortexscript:
  cmd.script:
    - source: salt://hive/thehive/scripts/cortex_init
    - cwd: /opt/so
    - template: jinja

so-thehive:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-thehive:{{ VERSION }}
    - environment:
      - ELASTICSEARCH_HOST={{ MASTERIP }}
    - hostname: so-thehive
    - name: so-thehive
    - user: 939
    - binds:
      - /opt/so/conf/hive/etc/application.conf:/opt/thehive/conf/application.conf:ro
    - port_bindings:
      - 0.0.0.0:9000:9000

hivescript:
  cmd.script:
    - source: salt://hive/thehive/scripts/hive_init
    - cwd: /opt/so
    - template: jinja
