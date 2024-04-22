{# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
https://securityonion.net/license; you may not use this file except in compliance with the
Elastic License 2.0. #}

{% set minionid = data['id'].split('_')[0] %}
{% set role = data['data']['process_x_roles'] %}

{# Run so-yaml to replace kafka.node.<minionID>.role with the value from kafka/controllers.sls #}

update_global_kafka_pillar:
  local.cmd.run:
    - tgt: 'G@role:so-manager or G@role:so-managersearch or G@role:so-standalone'
    - tgt_type: compound
    - arg:
      - '/usr/sbin/so-yaml.py replace /opt/so/saltstack/local/pillar/kafka/nodes.sls kafka.nodes.{{ minionid }}.role {{ role }}'