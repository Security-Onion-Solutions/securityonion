# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{# Fires on salt/key. Only act on successful key acceptance — not reauth. #}
{% if data.get('act') == 'accept' and data.get('result') == True and data.get('id') %}

{{ data['id'] }}_telegraf_pg_sync:
  runner.state.orchestrate:
    - args:
      - mods: orch.telegraf_postgres_sync
      - pillar:
          postgres_fanout_minion: {{ data['id'] }}

{% do salt.log.info('telegraf_user_sync reactor: syncing telegraf PG user for minion %s' % data['id']) %}

{% endif %}
