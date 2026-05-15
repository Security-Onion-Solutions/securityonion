# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.

{% set GRIDNODETOKEN = salt['pillar.get']('global:fleet_grid_enrollment_token_general') -%}
{% if grains.role == 'so-heavynode' %}
{%   set GRIDNODETOKEN = salt['pillar.get']('global:fleet_grid_enrollment_token_heavy') -%}
{% endif %}

{% set AGENT_STATUS = salt['service.available']('elastic-agent') %}
{% set AGENT_EXISTS = salt['file.file_exists']('/opt/Elastic/Agent/elastic-agent') %}

{% if not AGENT_STATUS or not AGENT_EXISTS %}

pull_agent_installer:
  file.managed:
    - name: /opt/so/log/agents/so-elastic-agent_linux_amd64
    - source: salt://elasticfleet/files/so_agent-installers/so-elastic-agent_linux_amd64
    - mode: 755
    - makedirs: True

run_installer:
  cmd.run:
    {# Run agent installer and wait for it to report healthy status #}
    - name: ./so-elastic-agent_linux_amd64 -token={{ GRIDNODETOKEN }} -force -verify
    - cwd: /opt/so/log/agents
    - retry:
        attempts: 3
        interval: 20
    - require:
      - file: pull_agent_installer

cleanup_agent_installer:
  file.absent:
    - name: /opt/so/log/agents/so-elastic-agent_linux_amd64
{% endif %}
