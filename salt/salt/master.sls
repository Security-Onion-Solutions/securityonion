{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% from 'salt/map.jinja' import UPGRADECOMMAND %}
{% from 'salt/map.jinja' import SALTVERSION %}
{% from 'salt/map.jinja' import SALTNOTHELD %}
{% from 'salt/map.jinja' import INSTALLEDSALTVERSION %}
{% from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - salt.minion
{%   if GLOBALS.has_mom %}
  - salt.syndic
{%   endif %}

install_salt_master:
  pkg.installed:
    - name: salt-master
    - version: {{ SALTVERSION }}
    - update_holds: True

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

{# this will ensure the option gets set on a mom but will need to be revised since it will #}
{# also cause it to be set on a single manager setup without a mom #}
{# we can use the node_data pillar or nodegroups here to check if a node is a mom with managers below it #}
{% if not GLOBALS.has_mom %}
add_order_masters:
  file.append:
    - name: /etc/salt/master
    - text: |
        order_masters: True
    watch_in:
      service: salt_master_service
{% endif %}

salt_master_service:
  service.running:
    - name: salt-master
    - enable: True
    - watch:
      - file: checkmine_engine
      - file: engines_config
    - order: last

{# if you have a mom, sync down the salt state files #}
{% if grains.host != grains.master %}
{# these are the envs defined in master config under file_roots #}
{%   for env in ['default', 'local'] %}
{%     set dirs = [] %}
{%     for dir in salt['cp.list_master_dirs'](saltenv=env) %}
{%       set dir = dir.split('/')[0] %}
{%       if dir not in dirs %}
{%         do dirs.append(dir) %}
{{env}}_salt_state_directory_{{dir}}:
  file.recurse:
    - name: /opt/so/saltstack/{{env}}/salt/{{dir}}
    - source: salt://{{dir}}/
    - clean: True
    - makedirs: True
    - saltenv: {{env}}
{%       endif %}
{%     endfor %}
{%   endfor %}
{% endif %}


{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
