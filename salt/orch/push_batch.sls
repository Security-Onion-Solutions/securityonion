{% from 'salt/auto_apply.map.jinja' import AUTOAPPLY %}
{% set actions = salt['pillar.get']('actions', []) %}
{% set BATCH = AUTOAPPLY.batch %}
{# Must exceed gather_job_timeout (10s): at the 5s default, one saltutil.find_job reply slower than that abandons
   a queued state run, and a master slow to accept the publish gets it a second time. #}
{% set STATE_TIMEOUT = 60 %}

{# queue must be a top-level salt.state arg (kwarg is ignored); an int is max_queue and still fails on conflict #}
{# The first step of each action checks that its target is reachable: minions take up to ~22s to rejoin a
   restarted master's publisher, and each failed attempt takes ~15s to time out. salt.function does not count
   non-responders as failures, so the check passes as soon as any one minion answers. The drainer's 45s hold
   covers a restart before dispatch; the retry covers a restart during a running orchestration. expect_minions
   is not set on purpose: one offline node would then block the push to every node.
   A highstate checks with test.ping: it renders pillar itself, and the global and salt pillar actions push a
   highstate to '*', where an unbatched refresh_pillar would make every minion render pillar at once. A single
   state needs fresh pillar, so it checks with refresh_pillar. #}

{% for action in actions %}
{%   if action.get('highstate') %}
ping_{{ loop.index }}:
  salt.function:
    - name: test.ping
    - tgt: '{{ action.tgt }}'
    - tgt_type: {{ action.get('tgt_type', 'compound') }}
    - retry:
        attempts: 3
        interval: 10

apply_highstate_{{ loop.index }}:
  salt.state:
    - tgt: '{{ action.tgt }}'
    - tgt_type: {{ action.get('tgt_type', 'compound') }}
    - highstate: True
    - batch: {{ action.get('batch', BATCH) }}
    - queue: True
    - timeout: {{ STATE_TIMEOUT }}
    - require:
      - salt: ping_{{ loop.index }}
{%   else %}
refresh_pillar_{{ loop.index }}:
  salt.function:
    - name: saltutil.refresh_pillar
    - tgt: '{{ action.tgt }}'
    - tgt_type: {{ action.get('tgt_type', 'compound') }}
    - retry:
        attempts: 3
        interval: 10

apply_{{ action.state | replace('.', '_') }}_{{ loop.index }}:
  salt.state:
    - tgt: '{{ action.tgt }}'
    - tgt_type: {{ action.get('tgt_type', 'compound') }}
    - sls:
      - {{ action.state }}
    - batch: {{ action.get('batch', BATCH) }}
    - queue: True
    - timeout: {{ STATE_TIMEOUT }}
    - require:
      - salt: refresh_pillar_{{ loop.index }}
{%   endif %}
{% endfor %}
