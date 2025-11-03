# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.

{%- set GRIDNODETOKENGENERAL = salt['pillar.get']('global:fleet_grid_enrollment_token_general') -%}
{%- set GRIDNODETOKENHEAVY = salt['pillar.get']('global:fleet_grid_enrollment_token_heavy') -%}

{% set AGENT_STATUS = salt['service.available']('elastic-agent') %}
{% if not AGENT_STATUS  %}

pull_agent_installer:
  file.managed:
    - name: /opt/so/so-elastic-agent_linux_amd64
    - source: salt://elasticfleet/files/so_agent-installers/so-elastic-agent_linux_amd64
    - mode: 755
    - makedirs: True

{% if grains.role not in ['so-heavynode'] %}
run_installer:
  cmd.run:
    - name: ./so-elastic-agent_linux_amd64 -token={{ GRIDNODETOKENGENERAL }}
    - cwd: /opt/so
    - retry: True
{% else %} 
run_installer:
  cmd.run:
    - name: ./so-elastic-agent_linux_amd64 -token={{ GRIDNODETOKENHEAVY }}
    - cwd: /opt/so
    - retry: True
{% endif %}  

cleanup_agent_installer:
  file.absent:
    - name: /opt/so/so-elastic-agent_linux_amd64
{% endif %}
