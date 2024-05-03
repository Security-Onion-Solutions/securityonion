{% set MANAGER = salt['pillar.get']('setup:manager') %}
{% set NEWNODE = salt['pillar.get']('setup:newnode') %}

{{NEWNODE}}_update_mine:
  salt.function:
    - name: mine.update
    - tgt: {{ NEWNODE }}
    - retry:
        attempts: 24
        interval: 5

{% if NEWNODE.split('_')|last in ['searchnode', 'heavynode'] %}
manager_run_es_soc:
  salt.state:
    - tgt: {{ MANAGER }}
    - sls:
      - elasticsearch
      - soc
    - queue: True
    - retry:
        attempts: 3
        interval: 60
    - require:
        - salt: {{NEWNODE}}_update_mine
{% endif %}

{{NEWNODE}}_run_highstate:
  salt.state:
    - tgt: {{ NEWNODE }}
    - highstate: True
    - queue: True
    - retry:
        attempts: 5
        interval: 60

{{NEWNODE}}_set_highstate_cron:
  salt.state:
    - tgt: {{ NEWNODE }}
    - sls:
      - setup.highstate_cron
    - queue: True
    - onfail:
        - salt: {{NEWNODE}}_run_highstate
