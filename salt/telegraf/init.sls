{% set MASTER = salt['grains.get']('master') %}
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.2') %}

# Add Telegraf to monitor all the things.
tgraflogdir:
  file.directory:
    - name: /opt/so/log/telegraf
    - makedirs: True

tgrafetcdir:
  file.directory:
    - name: /opt/so/conf/telegraf/etc
    - makedirs: True

tgrafetsdir:
  file.directory:
    - name: /opt/so/conf/telegraf/scripts
    - makedirs: True

tgrafsyncscripts:
  file.recurse:
    - name: /opt/so/conf/telegraf/scripts
    - user: 939
    - group: 939
    - file_mode: 755
    - template: jinja
    - source: salt://telegraf/scripts

tgrafconf:
  file.managed:
    - name: /opt/so/conf/telegraf/etc/telegraf.conf
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://telegraf/etc/telegraf.conf

so-telegraf:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-telegraf:{{ VERSION }}
    - environment:
      - HOST_PROC=/host/proc
      - HOST_ETC=/host/etc
      - HOST_SYS=/host/sys
      - HOST_MOUNT_PREFIX=/host
    - network_mode: host
    - binds:
      - /opt/so/log/telegraf:/var/log/telegraf:rw
      - /opt/so/conf/telegraf/etc/telegraf.conf:/etc/telegraf/telegraf.conf:ro
      - /var/run/utmp:/var/run/utmp:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /:/host/root:ro
      - /sys:/host/sys:ro
      - /proc:/host/proc:ro
      - /nsm:/host/nsm:ro
      - /etc:/host/etc:ro
      {% if grains['role'] == 'so-master' or grains['role'] == 'so-eval' or grains['role'] == 'so-mastersearch' %}
      - /etc/pki/ca.crt:/etc/telegraf/ca.crt:ro
      {% else %}
      - /etc/ssl/certs/intca.crt:/etc/telegraf/ca.crt:ro
      {% endif %}
      - /etc/pki/influxdb.crt:/etc/telegraf/telegraf.crt:ro
      - /etc/pki/influxdb.key:/etc/telegraf/telegraf.key:ro
      - /opt/so/conf/telegraf/scripts:/scripts:ro
      - /opt/so/log/stenographer:/var/log/stenographer:ro
      - /opt/so/log/suricata:/var/log/suricata:ro
    - watch:
      - file: tgrafconf
      - file: tgrafsyncscripts