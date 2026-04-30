# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# Drops /etc/salt/master.d/ext_pillar_postgres.conf so the salt-master loads
# pillar overlays from the so_pillar.* schema in so-postgres alongside the
# on-disk SLS pillar tree. Gated on the postgres:so_pillar:enabled feature
# flag (default false) so the file only appears once the schema is deployed
# and the importer has run at least once.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

{% if salt['pillar.get']('postgres:so_pillar:enabled', False) %}

ext_pillar_postgres_config:
  file.managed:
    - name: /etc/salt/master.d/ext_pillar_postgres.conf
    - source: salt://salt/master/files/ext_pillar_postgres.conf.jinja
    - template: jinja
    - mode: '0640'
    - user: root
    - group: salt
    - watch_in:
      - service: salt_master_service

{% else %}

# When the flag is off make sure any previously-deployed config is removed
# so a rollback flips behavior cleanly.
ext_pillar_postgres_config_absent:
  file.absent:
    - name: /etc/salt/master.d/ext_pillar_postgres.conf
    - watch_in:
      - service: salt_master_service

{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
