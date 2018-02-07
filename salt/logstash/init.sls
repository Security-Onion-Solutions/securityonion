# Logstash Section

# Add Logstash user
logstash:
  user.present:
    - uid: 931
    - gid: 931
    - home: /opt/so/conf/logstash

# Copy all the files needed for logstash

file.directory:
  - name: /opt/so/conf/logstash
  - user: 931
  - group: 939

file.directory:
  - name: /opt/so/conf/logstash/conf.d
  - user: 931
  - group: 939

file.recurse:
  - name: /opt/so/conf/logstash
  - source: salt://sensor/files/logstash
  - user: 931
  - group: 939

file.directory:
  - name: /nsm/import
  - user: 931
  - group: 939

file.directory:
  - name: /nsm/logstash
  - user: 931
  - group: 939

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
      - LS_JAVA_OPTS="-Xms$LOGSTASH_HEAP -Xmx$LOGSTASH_HEAP"
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
      - /nsm/logstash:/usr/share/logstash/data/
      - /opt/so/log/logstash:/var/log/logstash
    - network_mode: so-elastic-net
