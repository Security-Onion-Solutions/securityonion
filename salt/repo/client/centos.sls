# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'repo/client/map.jinja' import ABSENTFILES with context %}
{% from 'repo/client/map.jinja' import REPOPATH with context %}

{% if GLOBALS.os == 'CentOS Stream' %}

{% if ABSENTFILES|length > 0%}
  {% for file in ABSENTFILES  %}
{{ file }}:
  file.absent:
    - name: {{ REPOPATH }}{{ file }}
    - onchanges_in:
      - cmd: cleanyum
  {% endfor %}
{% endif %}

cleanyum:
  cmd.run:
    - name: 'yum clean all'
    - onchanges:
      - so_repo
      
yumconf:
  file.managed:
    - name: /etc/yum.conf
    - source: salt://repo/client/files/centos/yum.conf.jinja
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
    - name: /etc/pki/rpm_gpg
    - source: salt://repo/client/files/centos/keys/


  {% if GLOBALS.role in GLOBALS.manager_roles %}
so_repo:
  pkgrepo.managed:
    - name: securityonion
    - humanname: Security Onion Repo
    - baseurl: file:///nsm/repo/
    - enabled: 1
    - gpgcheck: 1

  {% else %}
so_repo:
  pkgrepo.managed:
    - name: securityonion
    - humanname: Security Onion Repo
    - baseurl: https://{{ GLOBALS.manager }}/repo
    - enabled: 1
    - gpgcheck: 1 

  {% endif %}

{% endif %}
  
# TODO: Add a pillar entry for custom repos








