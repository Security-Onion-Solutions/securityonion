{% set MANAGER = salt['pillar.get']('setup:manager') %}
{% set SEARCHNODE = salt['pillar.get']('setup:searchnode') %}

manager_run_es_soc:
  salt.state:
    - tgt: {{ MANAGER }}
    - sls:
      - elasticsearch
      - soc

searchnode_run_highstate:
  salt.state:
    - tgt: {{ SEARCHNODE }}
    - highstate: True
    - require:
      - salt: manager_run_es_soc
