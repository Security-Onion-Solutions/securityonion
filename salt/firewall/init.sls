{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

create_sysconfig_iptables:
  file.touch:
    - name: /etc/sysconfig/iptables
    - makedirs: True
    - unless: 'ls /etc/sysconfig/iptables'

iptables_config:
  file.managed:
    - name: /etc/sysconfig/iptables
    - source: salt://firewall/iptables.jinja
    - template: jinja

iptables_restore:
  cmd.run:
    - name: iptables-restore < /etc/sysconfig/iptables

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
