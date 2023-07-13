# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.

{%- set GRIDNODETOKENGENERAL = salt['pillar.get']('global:fleet_grid_enrollment_token_general') -%}
{%- set GRIDNODETOKENHEAVY = salt['pillar.get']('global:fleet_grid_enrollment_token_heavy') -%}

{% set AGENT_STATUS = salt['service.available']('elastic-agent') %}
{% if not AGENT_STATUS  %}

{% if grains.role not in ['so-heavynode'] %}
run_installer:
  cmd.script:
    - name: salt://elasticfleet/files/so_agent-installers/so-elastic-agent_linux_amd64
    - cwd: /opt/so
    - args: -token={{ GRIDNODETOKENGENERAL }}
    - retry: True
{% else %} 
run_installer:
  cmd.script:
    - name: salt://elasticfleet/files/so_agent-installers/so-elastic-agent_linux_amd64
    - cwd: /opt/so
    - args: -token={{ GRIDNODETOKENHEAVY }}
    - retry: True
{% endif %}  

{% endif %}
