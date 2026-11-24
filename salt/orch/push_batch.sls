{% from 'salt/auto_apply.map.jinja' import AUTOAPPLY %}
{% set actions = salt['pillar.get']('actions', []) %}
{% set BATCH = AUTOAPPLY.batch %}
{% set BATCH_WAIT = AUTOAPPLY.batch_wait %}

{# queue must be a top-level salt.state arg (kwarg is ignored); an int is max_queue and still fails on conflict #}

{% for action in actions %}
{%   if action.get('highstate') %}
apply_highstate_{{ loop.index }}:
  salt.state:
    - tgt: '{{ action.tgt }}'
    - tgt_type: {{ action.get('tgt_type', 'compound') }}
    - highstate: True
    - batch: {{ action.get('batch', BATCH) }}
    - batch_wait: {{ action.get('batch_wait', BATCH_WAIT) }}
    - queue: True
{%   else %}
refresh_pillar_{{ loop.index }}:
  salt.function:
    - name: saltutil.refresh_pillar
    - tgt: '{{ action.tgt }}'
    - tgt_type: {{ action.get('tgt_type', 'compound') }}

apply_{{ action.state | replace('.', '_') }}_{{ loop.index }}:
  salt.state:
    - tgt: '{{ action.tgt }}'
    - tgt_type: {{ action.get('tgt_type', 'compound') }}
    - sls:
      - {{ action.state }}
    - batch: {{ action.get('batch', BATCH) }}
    - batch_wait: {{ action.get('batch_wait', BATCH_WAIT) }}
    - queue: True
    - require:
      - salt: refresh_pillar_{{ loop.index }}
{%   endif %}
{% endfor %}
