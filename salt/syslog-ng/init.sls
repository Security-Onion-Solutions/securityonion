# Sync the Files
file.directory:
  - name: /opt/so/conf/syslog-ng
  - user: 939
  - group: 939

# Syslog-ng Docker

so-syslog-ng:
  dockerng.running:
    - image: pillaritem/so-logstash
    - hostname: syslog-ng
    - priviledged: true
    - ports:
      - 514/tcp
      - 514/udp
      - 601
    - network_mode: so-elastic-net
