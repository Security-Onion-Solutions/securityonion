{% set MANAGER = salt['pillar.get']('setup:manager') %}
{% set NEWNODE = salt['pillar.get']('setup:newnode') %}

# tell the minion to populate the mine with data from mine_functions which is populated during setup
# this only needs to happen on non managers since they handle this during setup
# and they need to wait for ca creation to update the mine
{{NEWNODE}}_update_mine:
  salt.function:
    - name: mine.update
    - tgt: {{ NEWNODE }}
    - retry:
        attempts: 36
        interval: 5

# so-minion's setupMinionFiles rebuilds the new minion's pillar file from
# scratch, wiping any postgres.telegraf.* entries the reactor may have written
# on salt-key accept. Re-fan the cred here so the highstate below sees it.
# Idempotent via the unless: guard in postgres.auth.
manager_fanout_postgres_telegraf_{{NEWNODE}}:
  salt.state:
    - tgt: {{ MANAGER }}
    - sls:
      - postgres.auth
    - queue: True
    - pillar:
        postgres_fanout_minion: {{ NEWNODE }}
    - require:
      - salt: {{NEWNODE}}_update_mine

# we need to prepare the manager for a new searchnode or heavynode
{% if NEWNODE.split('_')|last in ['searchnode', 'heavynode'] %}
manager_run_es_soc:
  salt.state:
    - tgt: {{ MANAGER }}
    - sls:
      - elasticsearch
      - soc
    - queue: True
    - require:
        - salt: {{NEWNODE}}_update_mine
{% endif %}

{{NEWNODE}}_run_highstate:
  salt.state:
    - tgt: {{ NEWNODE }}
    - highstate: True
    - queue: True
    - require:
      - salt: manager_fanout_postgres_telegraf_{{NEWNODE}}
