# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.

{% from 'repo/client/map.jinja' import ABSENTFILES with context %}
{% from 'repo/client/map.jinja' import REPOPATH with context %}
{% from 'vars/globals.map.jinja' import GLOBALS %}

{% set role = grains.id.split('_') | last %}
{% set MANAGER = salt['grains.get']('master') %}
{% if grains['os'] == 'Rocky' %}

{% if ABSENTFILES|length > 0%}
  {% for file in ABSENTFILES  %}
{{ file }}:
  file.absent:
    - name: {{ REPOPATH }}{{ file }}
    - onchanges_in:
      - cmd: cleandnf
  {% endfor %}
{% endif %}

cleandnf:
  cmd.run:
    - name: 'dnf clean all'
    - onchanges:
      - so_repo
      
yumconf:
  file.managed:
    - name: /etc/yum.conf
    - source: salt://repo/client/files/rocky/yum.conf.jinja
    - mode: 644
    - template: jinja
    - show_changes: False

repair_yumdb:
  cmd.run:
    - name: 'mv -f /var/lib/rpm/__db* /tmp && yum clean all'
    - onlyif:
      - 'yum check-update 2>&1 | grep "Error: rpmdb open failed"'

crsynckeys:
  file.recurse:
    - name: /etc/pki/rpm-gpg
    - source: salt://repo/client/files/rocky/keys/

so_repo:
  pkgrepo.managed:
    - name: securityonion
    - humanname: Security Onion Repo
  {% if GLOBALS.role in ['so-eval', 'so-standalone', 'so-import', 'so-manager', 'so-managersearch'] %}
    - baseurl: file:///nsm/repo/
  {% else %}
    - baseurl: https://{{ GLOBALS.repo_host }}/repo
  {% endif %}
    - enabled: 1
    - gpgcheck: 1

{% endif %}
  
# TODO: Add a pillar entry for custom repos
