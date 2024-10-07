# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% if sls.split('.')[0] in allowed_states %}
{% from 'elasticfleet/map.jinja' import ELASTICFLEETMERGED %}
{% set node_data = salt['pillar.get']('node_data') %}

# Add EA Group
elasticfleetgroup:
  group.present:
    - name: elastic-fleet
    - gid: 947

# Add EA user
elastic-fleet:
  user.present:
    - uid: 947
    - gid: 947
    - home: /opt/so/conf/elastic-fleet
    - createhome: False

elasticfleet_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://elasticfleet/tools/sbin
    - user: 947
    - group: 939
    - file_mode: 755

elasticfleet_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://elasticfleet/tools/sbin_jinja
    - user: 947
    - group: 939 
    - file_mode: 755
    - template: jinja
    - exclude_pat:
      - so-elastic-fleet-package-upgrade # exclude this because we need to watch it for changes

eaconfdir:
  file.directory:
    - name: /opt/so/conf/elastic-fleet
    - user: 947
    - group: 939
    - makedirs: True

ealogdir:
  file.directory:
    - name: /opt/so/log/elasticfleet
    - user: 947
    - group: 939
    - makedirs: True

eastatedir:
  file.directory:
    - name: /opt/so/conf/elastic-fleet/state
    - user: 947
    - group: 939
    - makedirs: True

eapackageupgrade:
  file.managed:
    - name: /usr/sbin/so-elastic-fleet-package-upgrade
    - source: salt://elasticfleet/tools/sbin_jinja/so-elastic-fleet-package-upgrade
    - user: 947
    - group: 939
    - mode: 755
    - template: jinja

{%   if GLOBALS.role != "so-fleet" %}

soresourcesrepoconfig:
  git.config_set:
    - name: safe.directory
    - value: /nsm/securityonion-resources
    - global: True
    - user: socore
    
{% if not GLOBALS.airgap %}
soresourcesrepoclone:
  git.latest:
    - name: https://github.com/Security-Onion-Solutions/securityonion-resources.git
    - target: /nsm/securityonion-resources
    - rev: 'main'
    - depth: 1
    - force_reset: True
{% endif %}

elasticdefendconfdir:
  file.directory:
    - name: /opt/so/conf/elastic-fleet/defend-exclusions/rulesets
    - user: 947
    - group: 939
    - makedirs: True
  
elasticdefenddisabled:
  file.managed:
    - name: /opt/so/conf/elastic-fleet/defend-exclusions/disabled-filters.yaml
    - source: salt://elasticfleet/files/soc/elastic-defend-disabled-filters.yaml
    - user: 947
    - group: 939
    - mode: 600

elasticdefendcustom:
  file.managed:
    - name: /opt/so/conf/elastic-fleet/defend-exclusions/rulesets/custom-filters-raw
    - source: salt://elasticfleet/files/soc/elastic-defend-custom-filters.yaml
    - user: 947
    - group: 939
    - mode: 600

{% if ELASTICFLEETMERGED.config.defend_filters.enable_auto_configuration %}
{%   set ap = "present" %}
{% else %}
{%   set ap = "absent" %}
{% endif %}
cron-elastic-defend-filters:
  cron.{{ap}}:
    - name: python3 /sbin/so-elastic-defend-manage-filters.py -c /opt/so/conf/elasticsearch/curl.config -d /opt/so/conf/elastic-fleet/defend-exclusions/disabled-filters.yaml -i /nsm/securityonion-resources/event_filters/ -i /opt/so/conf/elastic-fleet/defend-exclusions/rulesets/custom-filters/ &>> /opt/so/log/elasticfleet/elastic-defend-manage-filters.log
    - identifier: elastic-defend-filters
    - user: root
    - minute: '0'
    - hour: '3'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

eaintegrationsdir:
  file.directory:
    - name: /opt/so/conf/elastic-fleet/integrations
    - user: 947
    - group: 939
    - makedirs: True

eadynamicintegration:
  file.recurse:
    - name: /opt/so/conf/elastic-fleet/integrations
    - source: salt://elasticfleet/files/integrations-dynamic
    - user: 947
    - group: 939
    - template: jinja

eaintegration:
  file.recurse:
    - name: /opt/so/conf/elastic-fleet/integrations
    - source: salt://elasticfleet/files/integrations
    - user: 947
    - group: 939

eaoptionalintegrationsdir:
  file.directory:
    - name: /opt/so/conf/elastic-fleet/integrations-optional
    - user: 947
    - group: 939
    - makedirs: True

{% for minion in node_data %}
{% set role = node_data[minion]["role"] %}
{% if role in [ "eval","fleet","heavynode","import","manager","managersearch","standalone" ] %}
{% set optional_integrations = ELASTICFLEETMERGED.optional_integrations %}
{% set integration_keys = optional_integrations.keys() %}
fleet_server_integrations_{{ minion }}:
  file.directory:
    - name: /opt/so/conf/elastic-fleet/integrations-optional/FleetServer_{{ minion }}
    - user: 947
    - group: 939
    - makedirs: True
{% for integration in integration_keys %}
{% if 'enabled_nodes' in optional_integrations[integration]%}
{% set enabled_nodes = optional_integrations[integration]["enabled_nodes"] %}
{% if minion in enabled_nodes %}
optional_integrations_dynamic_{{ minion }}_{{ integration }}:
  file.managed:
    - name: /opt/so/conf/elastic-fleet/integrations-optional/FleetServer_{{ minion }}/{{ integration }}.json
    - source: salt://elasticfleet/files/integrations-optional/{{ integration }}.json
    - user: 947
    - group: 939
    - template: jinja
    - defaults:
        NAME: {{ minion }}
{% else %}
optional_integrations_dynamic_{{ minion }}_{{ integration }}_delete:
  file.absent:
    - name: /opt/so/conf/elastic-fleet/integrations-optional/FleetServer_{{ minion }}/{{ integration }}.json
{% endif %}
{% endif %}
{% endfor %}
{% endif %}
{% endfor %}
ea-integrations-load:
  file.absent:
    - name: /opt/so/state/eaintegrations.txt
    - onchanges:
      - file: eaintegration
      - file: eadynamicintegration
      - file: /opt/so/conf/elastic-fleet/integrations-optional/*
{% endif %}
{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
