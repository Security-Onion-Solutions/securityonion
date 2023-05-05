{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

include:
  - zeek.sostatus
  
so-zeek:
  docker_container.absent:
    - force: True

so-zeek_so-status.disabled:
  file.comment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-zeek$

zeekpacketlosscron:
  cron.absent:
    - name: /usr/local/bin/packetloss.sh
    - identifier: zeekpacketlosscron
    - user: root

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
