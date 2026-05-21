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

# so-minion has already added the new minion's entry to telegraf/creds.sls
# via so-telegraf-cred before this orch fires. Reconcile the Postgres role
# on the manager so the new minion can authenticate on its first highstate,
# then refresh the minion's pillar so its telegraf.conf renders with the
# freshly-written cred.
manager_create_postgres_telegraf_role:
  salt.state:
    - tgt: {{ MANAGER }}
    - sls:
      - postgres.telegraf_users
    - queue: True
    - require:
      - salt: {{NEWNODE}}_update_mine

{{NEWNODE}}_refresh_pillar:
  salt.function:
    - name: saltutil.refresh_pillar
    - tgt: {{ NEWNODE }}
    - kwarg:
        wait: True
    - require:
      - salt: manager_create_postgres_telegraf_role

{{NEWNODE}}_run_highstate:
  salt.state:
    - tgt: {{ NEWNODE }}
    - highstate: True
    - queue: True
    - require:
      - salt: {{NEWNODE}}_refresh_pillar
