# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.

{% from 'repo/client/map.jinja' import ABSENTFILES with context %}
{% from 'repo/client/map.jinja' import REPOPATH with context %}
{% from 'vars/globals.map.jinja' import GLOBALS %}

{% import_yaml 'salt/minion.defaults.yaml' as saltversion %}
{% set saltversion = saltversion.salt.minion.version %}
{% set INSTALLEDSALTVERSION = grains.saltversion %}

{% set role = grains.id.split('_') | last %}
{% set MANAGER = salt['grains.get']('master') %}
{% if grains['os'] == 'OEL' %}

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
    - source: salt://repo/client/files/oracle/yum.conf.jinja
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
    - source: salt://repo/client/files/oracle/keys/

so_repo:
  pkgrepo.managed:
    - name: securityonion
    - humanname: Security Onion Repo
  {% if GLOBALS.is_manager %}
    - baseurl: file:///nsm/repo/
  {% else %}
    - baseurl: https://{{ GLOBALS.repo_host }}/repo
  {% endif %}
    - enabled: 1
    - gpgcheck: 1

# Only assign the kernel repo once this node's running salt matches the version this
# SO release ships. During a soup the grid is mid-salt-upgrade; gating here keeps the
# UEK8 kernel repo (and the kernel update it enables) from activating until the node is
# fully on the target salt, the same way other states defer across the upgrade window.
{% if saltversion | string == INSTALLEDSALTVERSION | string %}
so_kernel_repo:
  pkgrepo.managed:
    - name: securityonionkernel
    - humanname: Security Onion Kernel Repo
  {% if GLOBALS.is_manager %}
    - baseurl: file:///nsm/kernelrepo/
  {% else %}
    - baseurl: https://{{ GLOBALS.repo_host }}/kernelrepo
  {% endif %}
    - enabled: 1
    - gpgcheck: 1
    # Supplementary kernel repo: tolerate it being empty/unreachable (e.g. before the
    # manager has populated /nsm/kernelrepo) so a missing repomd.xml can't make every
    # dnf/pkg operation on the grid fail.
    - skip_if_unavailable: 1
    # Only assign the kernel repo once physical NIC names are pinned by MAC, so the
    # UEK8 kernel update can't renumber interfaces SO binds by name (see pin_nic_names
    # in salt/common/init.sls, which drops this marker via /usr/sbin/so-nic-pin).
    - onlyif: 'test -e /opt/so/state/nic_names_pinned'
{% endif %}

{% endif %}
  
# TODO: Add a pillar entry for custom repos
