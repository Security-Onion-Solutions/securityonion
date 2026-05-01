# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# Deploys the pg_notify_pillar engine module + its master.d config so the
# salt-master subscribes to so_pillar.change_queue and republishes changes
# on the salt event bus as so/pillar/changed. Reactor (so_pillar_changed.sls)
# matches that tag and dispatches the appropriate orch.
#
# Gated on the same postgres:so_pillar:enabled flag as the schema and
# ext_pillar config so the three components flip together.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

{% if salt['pillar.get']('postgres:so_pillar:enabled', False) %}

pg_notify_pillar_engine_module:
  file.managed:
    - name: /etc/salt/engines/pg_notify_pillar.py
    - source: salt://salt/engines/master/pg_notify_pillar.py
    - mode: '0644'
    - user: root
    - group: root
    - makedirs: True
    - watch_in:
      - service: salt_master_service

pg_notify_pillar_engine_config:
  file.managed:
    - name: /etc/salt/master.d/pg_notify_pillar_engine.conf
    - source: salt://salt/master/files/pg_notify_pillar_engine.conf.jinja
    - template: jinja
    - mode: '0640'
    - user: root
    - group: salt
    - watch_in:
      - service: salt_master_service

pg_notify_pillar_reactor_config:
  file.managed:
    - name: /etc/salt/master.d/so_pillar_reactor.conf
    - source: salt://salt/master/files/so_pillar_reactor.conf
    - mode: '0644'
    - user: root
    - group: root
    - watch_in:
      - service: salt_master_service

{% else %}

# When the flag flips off, peel everything back so a rollback returns to
# pure-disk pillar with no orphan engine churning on a dead listen socket.
pg_notify_pillar_engine_module_absent:
  file.absent:
    - name: /etc/salt/engines/pg_notify_pillar.py
    - watch_in:
      - service: salt_master_service

pg_notify_pillar_engine_config_absent:
  file.absent:
    - name: /etc/salt/master.d/pg_notify_pillar_engine.conf
    - watch_in:
      - service: salt_master_service

pg_notify_pillar_reactor_config_absent:
  file.absent:
    - name: /etc/salt/master.d/so_pillar_reactor.conf
    - watch_in:
      - service: salt_master_service

{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
