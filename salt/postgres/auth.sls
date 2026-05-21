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

# Admin cred only. Per-minion Telegraf creds live in telegraf/creds.sls,
# managed by /usr/sbin/so-telegraf-cred (called from so-minion).
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
    - show_changes: False
{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
