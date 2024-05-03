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
    - kwarg:
        queue: True
    - retry:
        attempts: 30
        interval: 10
    - require:
        - salt: new_node_update_mine
{% endif %}

{{NEWNODE}}_run_highstate:
  salt.state:
    - tgt: {{ NEWNODE }}
    - highstate: True
    - kwarg:
        queue: True
    - retry:
        attempts: 30
        interval: 10
