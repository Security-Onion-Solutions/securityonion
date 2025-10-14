# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% set nsm_exists = salt['file.directory_exists']('/nsm') %}
{% if nsm_exists %}
{%   set nsm_total = salt['cmd.shell']('df -BG /nsm | tail -1 | awk \'{print $2}\'') %}

nsm_total:
  grains.present:
    - name: nsm_total
    - value: {{ nsm_total }}

{% else %}

nsm_missing:
  test.succeed_without_changes:
    - name: /nsm does not exist, skipping grain assignment

{% endif %}
