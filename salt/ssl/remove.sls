# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

trusttheca:
  file.absent:
    - name: /etc/pki/tls/certs/intca.crt

symlinkca:
  file.absent:
    - name: /etc/ssl/certs/intca.crt

influxdb_key:
  file.absent:
    - name: /etc/pki/influxdb.key

influxdb_crt:
  file.absent:
    - name: /etc/pki/influxdb.crt

telegraf_key:
  file.absent:
    - name: /etc/pki/telegraf.key

telegraf_crt:
  file.absent:
    - name: /etc/pki/telegraf.crt

redis_key:
  file.absent:
    - name: /etc/pki/redis.key

redis_crt:
  file.absent:
    - name: /etc/pki/redis.crt

etc_filebeat_key:
  file.absent:
    - name: /etc/pki/filebeat.key

etc_filebeat_crt:
  file.absent:
    - name: /etc/pki/filebeat.crt

filebeatdir:
  file.absent:
    - name: /opt/so/saltstack/local/salt/filebeat/files

registry_key:
  file.absent:
    - name: /etc/pki/registry.key

registry_crt:
  file.absent:
    - name: /etc/pki/registry.crt

elasticsearch_key:
  file.absent:
    - name: /etc/pki/elasticsearch.key

elasticsearch_crt:
  file.absent:
    - name: /etc/pki/elasticsearch.crt

remove_elasticsearch.p12:
  file.absent:
    - name: /etc/pki/elasticsearch.p12

managerssl_key:
  file.absent:
    - name: /etc/pki/managerssl.key

managerssl_crt:
  file.absent:
    - name: /etc/pki/managerssl.crt

fleet_key:
  file.absent:
    - name: /etc/pki/fleet.key

fleet_crt:
  file.absent:
    - name: /etc/pki/fleet.crt

fbcertdir:
  file.absent:
    - name: /opt/so/conf/filebeat/etc/pki

kafka_crt:
  file.absent:
    - name: /etc/pki/kafka.crt

kafka_key:
  file.absent:
    - name: /etc/pki/kafka.key

kafka_logstash_crt:
  file.absent:
    - name: /etc/pki/kafka-logstash.crt

kafka_logstash_key:
  file.absent:
    - name: /etc/pki/kafka-logstash.key

kafka_logstash_keystore:
  file.absent:
    - name: /etc/pki/kafka-logstash.p12

elasticfleet_agent_crt:
  file.absent:
    - name: /etc/pki/elasticfleet-agent.crt

elasticfleet_agent_key:
  file.absent:
    - name: /etc/pki/elasticfleet-agent.key

elasticfleet_agent_p8:
  file.absent:
    - name: /etc/pki/elasticfleet-agent.p8

elasticfleet_kafka_crt:
  file.absent:
    - name: /etc/pki/elasticfleet-kafka.crt

elasticfleet_kafka_key:
  file.absent:
    - name: /etc/pki/elasticfleet-kafka.key

elasticfleet_logstash_crt:
  file.absent:
    - name: /etc/pki/elasticfleet-logstash.crt

elasticfleet_logstash_key:
  file.absent:
    - name: /etc/pki/elasticfleet-logstash.key

elasticfleet_logstash_p8:
  file.absent:
    - name: /etc/pki/elasticfleet-logstash.p8

elasticfleet_lumberjack_crt:
  file.absent:
    - name: /etc/pki/elasticfleet-lumberjack.crt

elasticfleet_lumberjack_key:
  file.absent:
    - name: /etc/pki/elasticfleet-lumberjack.key

elasticfleet_lumberjack_p8:
  file.absent:
    - name: /etc/pki/elasticfleet-lumberjack.p8

elasticfleet_server_crt:
  file.absent:
    - name: /etc/pki/elasticfleet-server.crt

elasticfleet_server_key:
  file.absent:
    - name: /etc/pki/elasticfleet-server.key

filebeat_p8:
  file.absent:
    - name: /etc/pki/filebeat.p8
