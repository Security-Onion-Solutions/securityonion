# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.

{% set GRIDNODETOKENGENERAL = salt['pillar.get']('global:fleet_grid_enrollment_token_general') %}
{% set GRIDNODETOKENHEAVY = salt['pillar.get']('global:fleet_grid_enrollment_token_heavy') %}

{% if GLOBALS.role == 'so-heavynode' %}
{%   set GRIDNODETOKEN = salt['pillar.get']('global:fleet_grid_enrollment_token_heavy') %}
{% else %}
{%   set GRIDNODETOKEN = salt['pillar.get']('global:fleet_grid_enrollment_token_general') %}
{% endif %}

{% set AGENT_STATUS = salt['service.available']('elastic-agent') %}
{% if not AGENT_STATUS %}

run_installer:
  cmd.script:
    - name: salt://elasticfleet/files/so_agent-installers/so-elastic-agent_linux_amd64
    - cwd: /opt/so
    - args: -token={{ GRIDNODETOKEN }}
    - retry:
        attempts: 12
        interval: 5

{% endif %}
