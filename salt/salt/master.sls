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

master_config:
  file.managed:
    - name: /etc/salt/master
    - source: salt://salt/etc/master.jinja
    - template: jinja
    - defaults:
        GLOBALS: {{ GLOBALS }}
    - watch_in:
      - service: salt_master_service
{%   if GLOBALS.has_mom %}
      - service: salt_syndic_service
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

default_salt_state_directory:
  file.recurse:
    - name: /opt/so/saltstack/default/salt/
    - source: salt://salt
    - clean: True
    - makedirs: True
    - saltenv: default

local_salt_state_directory:
  file.recurse:
    - name: /opt/so/saltstack/local/salt/
    - source: salt://salt
    - makedirs: True
    - saltenv: local

# from the mom, sync this nodegroups pillars to the nodegroups manager
local_pillar_directory:
  file.recurse:
    - name: /opt/so/saltstack/local/pillar/
    - source: salt://salt/nodegroups/{{pillar.nodegroup.name}}
    - makedirs: True
    - saltenv: local

{% endif %}


{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
