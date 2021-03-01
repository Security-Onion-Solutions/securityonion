{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set MANAGER = salt['grains.get']('master') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}

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
    - user: root
    - group: 939
    - file_mode: 700
    - template: jinja
    - source: salt://telegraf/scripts
{% if salt['pillar.get']('global:mdengine', 'ZEEK') == 'SURICATA' %}
    - exclude_pat: zeekcaptureloss.sh
{% endif %}

tgrafconf:
  file.managed:
    - name: /opt/so/conf/telegraf/etc/telegraf.conf
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://telegraf/etc/telegraf.conf

so-telegraf:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-telegraf:{{ VERSION }}
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
    - watch:
      - file: tgrafconf
      - file: tgrafsyncscripts

append_so-telegraf_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-telegraf

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
