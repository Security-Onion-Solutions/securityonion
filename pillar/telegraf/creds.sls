# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# Per-minion Telegraf Postgres credentials. so-telegraf-cred on the manager is
# the single writer; it mutates /opt/so/saltstack/local/pillar/telegraf/creds.sls
# under flock. Pillar_roots order (local before default) means the populated
# copy shadows this default on any real grid; this file exists so the pillar
# key is always defined on fresh installs and when no minions have creds yet.
telegraf:
  postgres_creds: {}
