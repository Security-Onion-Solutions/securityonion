# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

so-curator:
  docker_container.absent:
    - force: True

so-curator_so-status.disabled:
  file.line:
    - name: /opt/so/conf/so-status/so-status.conf
    - match: ^so-curator$
    - mode: delete

so-curator-cluster-close:
  cron.absent:
    - identifier: so-curator-cluster-close

so-curator-cluster-delete:
  cron.absent:
    - identifier: so-curator-cluster-delete

delete_curator_configuration:
  file.absent:
    - name: /opt/so/conf/curator
    - recurse: True

{% set files = salt.file.find(path='/usr/sbin', name='so-curator*') %}
{% if files|length > 0 %}
delete_curator_scripts:
  file.absent:
    - names: {{files|yaml}}
{% endif %}