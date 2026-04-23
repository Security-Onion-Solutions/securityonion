# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKERMERGED %}
{%   from 'elasticfleet/map.jinja' import ELASTICFLEETMERGED %}

include:
  - elasticfleet.config

# If enabled, automatically update Fleet Logstash Outputs
{% if ELASTICFLEETMERGED.config.server.enable_auto_configuration and grains.role not in ['so-import', 'so-eval'] %}
so-elastic-fleet-auto-configure-logstash-outputs:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-outputs-update
    - retry:
        attempts: 4
        interval: 30

{# Separate from above in order to catch elasticfleet-logstash.crt changes and force update to fleet output policy #}
so-elastic-fleet-auto-configure-logstash-outputs-force:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-outputs-update --certs
    - retry:
        attempts: 4
        interval: 30
    - onchanges:
        - x509: etc_elasticfleet_logstash_crt
        - x509: elasticfleet_kafka_crt
{% endif %}

# If enabled, automatically update Fleet Server URLs & ES Connection
so-elastic-fleet-auto-configure-server-urls:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-urls-update
    - retry:
        attempts: 4
        interval: 30

# Automatically update Fleet Server Elasticsearch URLs & Agent Artifact URLs
so-elastic-fleet-auto-configure-elasticsearch-urls:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-es-url-update
    - retry:
        attempts: 4
        interval: 30

so-elastic-fleet-auto-configure-artifact-urls:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-artifacts-url-update
    - retry:
        attempts: 4
        interval: 30

so-elastic-fleet-package-statefile:
  file.managed:
    - name: /opt/so/state/elastic_fleet_packages.txt
    - contents: {{ELASTICFLEETMERGED.packages}}

so-elastic-fleet-package-upgrade:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-package-upgrade
    - retry:
        attempts: 3
        interval: 10
    - onchanges:
      - file: /opt/so/state/elastic_fleet_packages.txt

so-elastic-fleet-integrations:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-integration-policy-load
    - retry:
        attempts: 3
        interval: 10

so-elastic-agent-grid-upgrade:
  cmd.run:
    - name: /usr/sbin/so-elastic-agent-grid-upgrade
    - retry:
        attempts: 12
        interval: 5

so-elastic-fleet-integration-upgrade:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-integration-upgrade
    - retry:
        attempts: 3
        interval: 10

{# Optional integrations script doesn't need the retries like so-elastic-fleet-integration-upgrade which loads the default integrations #}
so-elastic-fleet-addon-integrations:
  cmd.run:
    - name: /usr/sbin/so-elastic-fleet-optional-integrations-load

{% if ELASTICFLEETMERGED.config.defend_filters.enable_auto_configuration %}
so-elastic-defend-manage-filters-file-watch:
  cmd.run:
    - name: python3 /sbin/so-elastic-defend-manage-filters.py -c /opt/so/conf/elasticsearch/curl.config -d /opt/so/conf/elastic-fleet/defend-exclusions/disabled-filters.yaml -i /nsm/securityonion-resources/event_filters/ -i /opt/so/conf/elastic-fleet/defend-exclusions/rulesets/custom-filters/ &>> /opt/so/log/elasticfleet/elastic-defend-manage-filters.log
    - onchanges:
      - file: elasticdefendcustom
      - file: elasticdefenddisabled
{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
