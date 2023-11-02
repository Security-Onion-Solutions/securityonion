{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% from 'salt/map.jinja' import UPGRADECOMMAND %}
{% from 'salt/map.jinja' import SALTVERSION %}
{% from 'salt/map.jinja' import SALTNOTHELD %}
{% from 'salt/map.jinja' import INSTALLEDSALTVERSION %}

include:
  - salt.minion

install_salt_master:
  pkg.installed:
    - name: salt-master
    - update_holds: True

{% if INSTALLEDSALTVERSION|string != SALTVERSION|string %}

{% if SALTNOTHELD | int == 0 %}
unhold_salt_master_package:
  module.run:
    - pkg.unhold:
      - pkgs:
        - salt-master
{% endif %}

install_salt_master:
  cmd.run:
    - name: |
        exec 0>&- # close stdin
        exec 1>&- # close stdout
        exec 2>&- # close stderr
        nohup /bin/sh -c '{{ UPGRADECOMMAND }}' &

{% endif %}

{% if INSTALLEDSALTVERSION|string == SALTVERSION|string %}

{% if SALTNOTHELD | int == 1 %}
hold_salt_master_package:
  module.run:
    - pkg.hold:
      - pkgs:
        - salt-master
{% endif %}
{% endif %}

ensure_local_salt:
  file.directory:
    - name: /opt/so/saltstack/local/salt/
    - user: socore
    - group: socore
    - dir_mode: 755
    - recurse:
      - user
      - group

ensure_local_pillar:
  file.directory:
    - name: /opt/so/saltstack/local/pillar/
    - user: socore
    - group: socore
    - dir_mode: 755
    - recurse:
      - user
      - group

# prior to 2.4.30 this engine ran on the manager with salt-minion
# this has changed to running with the salt-master in 2.4.30
remove_engines_config:
  file.absent:
    - name: /etc/salt/minion.d/engines.conf
    - source: salt://salt/files/engines.conf
    - watch_in:
      - service: salt_minion_service

checkmine_engine:
  file.managed:
    - name: /etc/salt/engines/checkmine.py
    - source: salt://salt/engines/master/checkmine.py
    - makedirs: True

engines_config:
  file.managed:
    - name: /etc/salt/master.d/engines.conf
    - source: salt://salt/files/engines.conf

salt_master_service:
  service.running:
    - name: salt-master
    - enable: True
    - watch:
      - file: checkmine_engine
      - file: engines_config
    - order: last

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
