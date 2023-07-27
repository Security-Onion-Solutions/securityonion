{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{%   from 'firewall/ipt.map.jinja' import iptmap %}

install_iptables:
  pkg.installed:
    - name: {{ iptmap.iptpkg }}

iptables_persist:
  pkg.installed:
    - name: {{ iptmap.persistpkg }}

iptables_service:
  service.running:
    - name: {{ iptmap.service }}
    - enable: True

create_sysconfig_iptables:
  file.touch:
    - name: {{ iptmap.configfile }}
    - makedirs: True
    - unless: 'ls {{ iptmap.configfile }}'

iptables_config:
  file.managed:
    - name: {{ iptmap.configfile }}
    - source: salt://firewall/iptables.jinja
    - template: jinja

{%   if grains.os_family == 'RedHat' %}
disable_firewalld:
  service.dead:
    - name: firewalld
    - enable: False
    - require:
      - file: iptables_config
{%   endif %}

iptables_restore:
  cmd.run:
    - name: iptables-restore < {{ iptmap.configfile }}
    - require:
      - file: iptables_config
    - onlyif:
      - iptables-restore --test {{ iptmap.configfile }}

{%   if grains.os_family == 'RedHat' %}
enable_firewalld:
  service.running:
    - name: firewalld
    - enable: True
    - onfail:
      - file: iptables_config
      - cmd: iptables_restore
{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
