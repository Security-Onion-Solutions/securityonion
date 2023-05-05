{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'telegraf/config.map.jinja' import TGMERGED %}

include:
  - ssl

# add Telegraf to monitor all the things
tgraflogdir:
  file.directory:
    - name: /opt/so/log/telegraf
    - makedirs: True
    - user: 939
    - group: 939
    - recurse:
      - user
      - group
      
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
    - user: root
    - group: 939
    - file_mode: 770
    - template: jinja
    - source: salt://telegraf/scripts
{% if GLOBALS.md_engine == 'SURICATA' %}
    - exclude_pat: zeekcaptureloss.sh
{% endif %}

telegraf_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://telegraf/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#telegraf_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://telegraf/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

tgrafconf:
  file.managed:
    - name: /opt/so/conf/telegraf/etc/telegraf.conf
    - user: 939
    - group: 939
    - mode: 660
    - template: jinja
    - source: salt://telegraf/etc/telegraf.conf
    - show_changes: False
    - defaults:
        GLOBALS: {{ GLOBALS }}
        TGMERGED: {{ TGMERGED }}

# this file will be read by telegraf to send node details (management interface, monitor interface, etc)
# into influx
node_config:
  file.managed:
    - name: /opt/so/conf/telegraf/node_config.json
    - source: salt://telegraf/node_config.json.jinja
    - template: jinja

so-telegraf:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-telegraf:{{ GLOBALS.so_version }}
    - user: 939
    - group_add: 939,920
    - environment:
      - HOST_PROC=/host/proc
      - HOST_ETC=/host/etc
      - HOST_SYS=/host/sys
      - HOST_MOUNT_PREFIX=/host
      - GODEBUG=x509ignoreCN=0
    - network_mode: host
    - init: True
    - binds:
      - /opt/so/log/telegraf:/var/log/telegraf:rw
      - /opt/so/conf/telegraf/etc/telegraf.conf:/etc/telegraf/telegraf.conf:ro
      - /opt/so/conf/telegraf/node_config.json:/etc/telegraf/node_config.json:ro
      - /var/run/utmp:/var/run/utmp:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /:/host/root:ro
      - /sys:/host/sys:ro
      - /proc:/host/proc:ro
      - /nsm:/host/nsm:ro
      - /etc:/host/etc:ro
      {% if grains['role'] == 'so-manager' or grains['role'] == 'so-eval' or grains['role'] == 'so-managersearch' %}
      - /etc/pki/ca.crt:/etc/telegraf/ca.crt:ro
      {% else %}
      - /etc/ssl/certs/intca.crt:/etc/telegraf/ca.crt:ro
      {% endif %}
      - /etc/pki/influxdb.crt:/etc/telegraf/telegraf.crt:ro
      - /etc/pki/influxdb.key:/etc/telegraf/telegraf.key:ro
      - /opt/so/conf/telegraf/scripts:/scripts:ro
      - /opt/so/log/stenographer:/var/log/stenographer:ro
      - /opt/so/log/suricata:/var/log/suricata:ro
      - /opt/so/log/raid:/var/log/raid:ro
      - /opt/so/log/sostatus:/var/log/sostatus:ro
    - watch:
      - file: tgrafconf
      - file: tgrafsyncscripts
      - file: node_config
    - require: 
      - file: tgrafconf
      - file: node_config
      {% if grains['role'] == 'so-manager' or grains['role'] == 'so-eval' or grains['role'] == 'so-managersearch' %}
      - x509: pki_public_ca_crt
      {% else %}
      - x509: trusttheca
      {% endif %}
      - x509: influxdb_crt
      - x509: influxdb_key
append_so-telegraf_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-telegraf

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
