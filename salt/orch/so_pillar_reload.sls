# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# Driven by the so_pillar_changed reactor. Translates a so_pillar.pillar_entry
# change into (cache.clear_pillar -> saltutil.refresh_pillar -> state.apply)
# on the appropriate target.
#
# Routing rules live in the DISPATCH map below — one entry per
# (pillar_path prefix) -> (state sls, role grain). Add new services here
# rather than wiring more reactors.
#
# Idempotent: state.apply is idempotent; if the pillar value didn't actually
# change anything observable, the affected state runs a no-op. Bulk imports
# and replays are safe.

{% set change       = salt['pillar.get']('so_pillar_change', {}) %}
{% set scope        = change.get('scope') %}
{% set role         = change.get('role_name') %}
{% set minion       = change.get('minion_id') %}
{% set changes      = change.get('changes', []) %}

{# (pillar_path prefix) -> {sls: <state to apply>, role: <role grain that runs it>}
   role is a grain value (e.g. 'so-sensor'), used to compute compound targets
   when the change is global or role-scoped. #}
{% set DISPATCH = {
    'suricata.':       {'sls': 'suricata.config',     'roles': ['so-sensor', 'so-heavynode', 'so-standalone']},
    'sensor.':         {'sls': 'suricata.config',     'roles': ['so-sensor', 'so-heavynode', 'so-standalone']},
    'zeek.':           {'sls': 'zeek.config',         'roles': ['so-sensor', 'so-heavynode', 'so-standalone']},
    'stenographer.':   {'sls': 'stenographer.config', 'roles': ['so-sensor', 'so-heavynode', 'so-standalone']},
    'pcap.':           {'sls': 'pcap.config',         'roles': ['so-sensor', 'so-heavynode', 'so-standalone']},
    'logstash.':       {'sls': 'logstash.config',     'roles': ['so-manager', 'so-managersearch', 'so-managerhype', 'so-receiver']},
    'redis.':          {'sls': 'redis.config',        'roles': ['so-manager', 'so-managersearch', 'so-managerhype', 'so-standalone']},
    'kafka.':          {'sls': 'kafka.config',        'roles': ['so-manager', 'so-managersearch', 'so-managerhype', 'so-receiver', 'so-searchnode']},
    'elasticsearch.':  {'sls': 'elasticsearch.config','roles': ['so-manager', 'so-managersearch', 'so-managerhype', 'so-searchnode', 'so-heavynode', 'so-standalone']},
    'kibana.':         {'sls': 'kibana.config',       'roles': ['so-manager', 'so-managersearch', 'so-managerhype', 'so-standalone']},
    'soc.':            {'sls': 'soc.config',          'roles': ['so-manager', 'so-managersearch', 'so-managerhype', 'so-standalone']},
    'telegraf.':       {'sls': 'telegraf.config',     'roles': ['*']},
    'fleet.':          {'sls': 'fleet.config',        'roles': ['so-fleet']},
    'strelka.':        {'sls': 'strelka.config',      'roles': ['so-sensor', 'so-heavynode', 'so-standalone']},
} %}

{# Collect a deduplicated set of (sls, target_kind) actions. target_kind is
   either 'minion:<id>' (scope=minion) or 'roles:so-x,so-y' (scope=role/global). #}
{% set actions = {} %}

{% for c in changes %}
{%   set path = c.get('pillar_path', '') %}
{%   for prefix, action in DISPATCH.items() %}
{%     if path.startswith(prefix) %}
{%       set sls = action['sls'] %}
{%       if scope == 'minion' and minion %}
{%         set key = sls ~ '|minion|' ~ minion %}
{%         set _ = actions.update({key: {'sls': sls, 'tgt': minion, 'tgt_type': 'glob'}}) %}
{%       else %}
{%         set role_targets = action['roles'] %}
{%         if '*' in role_targets %}
{%           set tgt = '*' %}
{%           set tgt_type = 'glob' %}
{%         else %}
{%           set tgt = ('I@role:' ~ role_targets|join(' or I@role:')) %}
{%           set tgt_type = 'compound' %}
{%         endif %}
{%         set key = sls ~ '|' ~ tgt %}
{%         set _ = actions.update({key: {'sls': sls, 'tgt': tgt, 'tgt_type': tgt_type}}) %}
{%       endif %}
{%     endif %}
{%   endfor %}
{% endfor %}

{% if actions %}

{% for key, action in actions.items() %}
{% set safe_id = loop.index0 | string %}

so_pillar_reload_clear_cache_{{ safe_id }}:
  salt.runner:
    - name: cache.clear_pillar
    - tgt: '{{ action.tgt }}'
    - tgt_type: '{{ action.tgt_type }}'

so_pillar_reload_refresh_pillar_{{ safe_id }}:
  salt.function:
    - name: saltutil.refresh_pillar
    - tgt: '{{ action.tgt }}'
    - tgt_type: '{{ action.tgt_type }}'
    - kwarg:
        wait: True
    - require:
      - salt: so_pillar_reload_clear_cache_{{ safe_id }}

so_pillar_reload_apply_state_{{ safe_id }}:
  salt.state:
    - tgt: '{{ action.tgt }}'
    - tgt_type: '{{ action.tgt_type }}'
    - sls:
      - {{ action.sls }}
    - queue: True
    - require:
      - salt: so_pillar_reload_refresh_pillar_{{ safe_id }}
{% endfor %}

{% else %}

{# No DISPATCH entry matched. Pillar still gets refreshed so any other states
   read fresh values, but no service-specific reload is invoked. #}
so_pillar_reload_unmapped_path_noop:
  test.nop
  {% do salt.log.info('orch.so_pillar_reload: no dispatch match for %s' % changes) %}

{% endif %}
