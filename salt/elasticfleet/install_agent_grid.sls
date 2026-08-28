# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.

{% set GRIDNODETOKEN = salt['pillar.get']('global:fleet_grid_enrollment_token_general') -%}
{% if grains.role == 'so-heavynode' %}
{%   set GRIDNODETOKEN = salt['pillar.get']('global:fleet_grid_enrollment_token_heavy') -%}
{% endif %}

{% set AGENT_STATUS = salt['service.available']('elastic-agent') %}
{% set AGENT_EXISTS = salt['file.file_exists']('/opt/Elastic/Agent/elastic-agent') %}

so-elastic-agent-install:
  file.managed:
    - name: /usr/sbin/so-elastic-agent-install
    - source: salt://elasticfleet/tools/sbin/so-elastic-agent-install
    - user: 947
    - group: 939
    - mode: 755
    - show_changes: False

{% if not AGENT_STATUS or not AGENT_EXISTS %}

pull_agent_installer:
  file.managed:
    - name: /opt/so/so-elastic-agent_linux_amd64
    - source: salt://elasticfleet/files/so_agent-installers/so-elastic-agent_linux_amd64
    - mode: 755
    - makedirs: True

run_installer:
  cmd.run:
    - name: /usr/sbin/so-elastic-agent-install "{{ GRIDNODETOKEN }}"
    - require:
      - file: pull_agent_installer

cleanup_agent_installer:
  file.absent:
    - name: /opt/so/so-elastic-agent_linux_amd64
{% endif %}
