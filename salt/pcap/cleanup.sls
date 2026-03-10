# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}

{% if GLOBALS.is_sensor %}

delete_so-steno_so-status.conf:
  file.line:
    - name: /opt/so/conf/so-status/so-status.conf
    - mode: delete
    - match: so-steno

remove_stenographer_user:
  user.absent:
    - name: stenographer
    - force: True

remove_stenographer_log_dir:
  file.absent:
    - name: /opt/so/log/stenographer

remove_stenoloss_script:
  file.absent:
    - name: /opt/so/conf/telegraf/scripts/stenoloss.sh

remove_steno_conf_dir:
  file.absent:
    - name: /opt/so/conf/steno

remove_so_pcap_export:
  file.absent:
    - name: /usr/sbin/so-pcap-export

remove_so_pcap_restart:
  file.absent:
    - name: /usr/sbin/so-pcap-restart

remove_so_pcap_start:
  file.absent:
    - name: /usr/sbin/so-pcap-start

remove_so_pcap_stop:
  file.absent:
    - name: /usr/sbin/so-pcap-stop

so-steno:
  docker_container.absent:
    - force: True

{% else %}

{{sls}}.non_sensor_node:
  test.show_notification:
    - text: "Stenographer cleanup not applicable on non-sensor nodes."

{% endif %}
