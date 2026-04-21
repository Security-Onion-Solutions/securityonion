# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

  {% set DIGITS = "1234567890" %}
  {% set LOWERCASE = "qwertyuiopasdfghjklzxcvbnm" %}
  {% set UPPERCASE = "QWERTYUIOPASDFGHJKLZXCVBNM" %}
  {% set SYMBOLS = "~!@#^&*()-_=+[]|;:,.<>?" %}
  {% set CHARS = DIGITS~LOWERCASE~UPPERCASE~SYMBOLS %}
  {% set so_postgres_user_pass = salt['pillar.get']('postgres:auth:users:so_postgres_user:pass', salt['random.get_str'](72, chars=CHARS)) %}

  {# Per-minion Telegraf Postgres credentials. Merge currently-up minions with any #}
  {# previously-known entries in pillar so existing passwords persist across runs. #}
  {% set existing = salt['pillar.get']('postgres:auth:users', {}) %}
  {% set up_minions = salt['saltutil.runner']('manage.up') or [] %}
  {% set telegraf_users = {} %}
  {% for key, entry in existing.items() %}
    {%- if key.startswith('telegraf_') and entry.get('user') and entry.get('pass') %}
      {%- do telegraf_users.update({key: entry}) %}
    {%- endif %}
  {% endfor %}
  {% for mid in up_minions %}
    {%- set safe = mid | replace('.','_') | replace('-','_') | lower %}
    {%- set key = 'telegraf_' ~ safe %}
    {%- if key not in telegraf_users %}
      {%- do telegraf_users.update({key: {'user': 'so_telegraf_' ~ safe, 'pass': salt['random.get_str'](72, chars=CHARS)}}) %}
    {%- endif %}
  {% endfor %}

postgres_auth_pillar:
  file.managed:
    - name: /opt/so/saltstack/local/pillar/postgres/auth.sls
    - mode: 640
    - reload_pillar: True
    - contents: |
        postgres:
          auth:
            users:
              so_postgres_user:
                user: so_postgres
                pass: "{{ so_postgres_user_pass }}"
              {% for key, entry in telegraf_users.items() %}
              {{ key }}:
                user: {{ entry.user }}
                pass: "{{ entry.pass }}"
              {% endfor %}
    - show_changes: False

  {# Fan a specific minion's telegraf cred out to its own pillar file.
     Two triggers populate the target list:
       - grains.id (always) so the manager's own pillar is populated on every
         postgres.auth run — otherwise the manager's telegraf has no cred on
         a fresh install and can't write to its own postgres.
       - pillar postgres_fanout_minion (when the reactor fires on a new
         minion's salt-key accept).
     The `unless` guard keeps re-runs idempotent, so this is one so-yaml.py
     check per target, not per minion in the grid. Bulk backfill for
     already-accepted minions lives in soup. #}
  {% set fanout_targets = [] %}
  {% if grains.id %}
  {%-   do fanout_targets.append(grains.id) %}
  {% endif %}
  {% set fanout_mid = salt['pillar.get']('postgres_fanout_minion') %}
  {% if fanout_mid and fanout_mid not in fanout_targets %}
  {%-   do fanout_targets.append(fanout_mid) %}
  {% endif %}

  {% for mid in fanout_targets %}
    {%- set safe = mid | replace('.','_') | replace('-','_') | lower %}
    {%- set key = 'telegraf_' ~ safe %}
    {%- set entry = telegraf_users.get(key) %}
    {%- if entry %}

postgres_telegraf_minion_pillar_{{ safe }}:
  cmd.run:
    - name: |
        set -e
        PILLAR_FILE=/opt/so/saltstack/local/pillar/minions/{{ mid }}.sls
        if [ ! -f "$PILLAR_FILE" ]; then
          echo '{}' > "$PILLAR_FILE"
          chown socore:socore "$PILLAR_FILE" 2>/dev/null || true
          chmod 640 "$PILLAR_FILE"
        fi
        /usr/sbin/so-yaml.py replace "$PILLAR_FILE" postgres.telegraf.user "$PG_USER"
        /usr/sbin/so-yaml.py replace "$PILLAR_FILE" postgres.telegraf.pass "$PG_PASS"
    - env:
      - PG_USER: '{{ entry.user }}'
      - PG_PASS: '{{ entry.pass }}'
    - unless: |
        [ "$(/usr/sbin/so-yaml.py get -r /opt/so/saltstack/local/pillar/minions/{{ mid }}.sls postgres.telegraf.user 2>/dev/null)" = '{{ entry.user }}' ]
    - require:
      - file: postgres_auth_pillar

    {%- endif %}
  {% endfor %}
{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
