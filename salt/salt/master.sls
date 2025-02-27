# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
#
# Note: Per the Elastic License 2.0, the second limitation states:
#
#   "You may not move, change, disable, or circumvent the license key functionality
#    in the software, and you may not remove or obscure any functionality in the
#    software that is protected by the license key."

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

include:
  - salt.minion
{%   if 'hvn' in salt['pillar.get']('features', []) %}
  - salt.cloud
  - salt.cloud.reactor_config_hypervisor

sync_runners:
  salt.runner:
    - name: saltutil.sync_runners
{% endif %}

hold_salt_master_package:
  module.run:
    - pkg.hold:
      - name: salt-master

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

pillarWatch_engine:
  file.managed:
    - name: /etc/salt/engines/pillarWatch.py
    - source: salt://salt/engines/master/pillarWatch.py

{%   if 'hvn' in salt['pillar.get']('features', []) %}
hvn_engine_config:
  file.managed:
    - name: /etc/salt/master.d/hvn_engine.conf
    - source: salt://salt/files/hvn_engine.conf
    - watch_in:
      - service: salt_master_service

virtual_node_manager_engine:
  file.managed:
    - name: /etc/salt/engines/virtual_node_manager.py
    - source: salt://salt/engines/master/virtual_node_manager.py
    - watch_in:
      - service: salt_master_service

virtual_power_manager_engine:
  file.managed:
    - name: /etc/salt/engines/virtual_power_manager.py
    - source: salt://salt/engines/master/virtual_power_manager.py
    - watch_in:
      - service: salt_master_service
{% endif %}

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
      - file: pillarWatch_engine
      - file: engines_config
    - order: last

{#
# we need to managed adding the following to salt-master config if there are hypervisors
reactor:
  - 'salt/key':
    - salt://reactor/check_hypervisor.sls
  - 'salt/cloud/*/deploying':
    - /opt/so/saltstack/default/salt/reactor/createEmptyPillar.sls
  - 'setup/so-minion':
    - /opt/so/saltstack/default/salt/reactor/sominion_setup.sls
  - 'salt/cloud/*/destroyed':
    - /opt/so/saltstack/default/salt/reactor/deleteKey.sls
#}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
