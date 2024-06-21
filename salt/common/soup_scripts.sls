# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% if '2.4' in salt['cp.get_file_str']('/etc/soversion') %}

{%   import_yaml '/opt/so/saltstack/local/pillar/global/soc_global.sls' as SOC_GLOBAL %}
{%   if SOC_GLOBAL.global.airgap %}
{%     set UPDATE_DIR='/tmp/soagupdate/SecurityOnion' %}
{%   else %}
{%     set UPDATE_DIR='/tmp/sogh/securityonion' %}
{%   endif %}

remove_common_soup:
  file.absent:
    - name: /opt/so/saltstack/default/salt/common/tools/sbin/soup

remove_common_so-firewall:
  file.absent:
    - name: /opt/so/saltstack/default/salt/common/tools/sbin/so-firewall

# This section is used to put the scripts in place in the Salt file system
# in case a state run tries to overwrite what we do in the next section.
copy_so-common_common_tools_sbin:
  file.copy:
    - name: /opt/so/saltstack/default/salt/common/tools/sbin/so-common
    - source: {{UPDATE_DIR}}/salt/common/tools/sbin/so-common
    - force: True
    - preserve: True

copy_so-image-common_common_tools_sbin:
  file.copy:
    - name: /opt/so/saltstack/default/salt/common/tools/sbin/so-image-common
    - source: {{UPDATE_DIR}}/salt/common/tools/sbin/so-image-common
    - force: True
    - preserve: True

copy_soup_manager_tools_sbin:
  file.copy:
    - name: /opt/so/saltstack/default/salt/manager/tools/sbin/soup
    - source: {{UPDATE_DIR}}/salt/manager/tools/sbin/soup
    - force: True
    - preserve: True

copy_so-firewall_manager_tools_sbin:
  file.copy:
    - name: /opt/so/saltstack/default/salt/manager/tools/sbin/so-firewall
    - source: {{UPDATE_DIR}}/salt/manager/tools/sbin/so-firewall
    - force: True
    - preserve: True

copy_so-yaml_manager_tools_sbin:
  file.copy:
    - name: /opt/so/saltstack/default/salt/manager/tools/sbin/so-yaml.py
    - source: {{UPDATE_DIR}}/salt/manager/tools/sbin/so-yaml.py
    - force: True
    - preserve: True

copy_so-repo-sync_manager_tools_sbin:
  file.copy:
    - name: /opt/so/saltstack/default/salt/manager/tools/sbin/so-repo-sync
    - source: {{UPDATE_DIR}}/salt/manager/tools/sbin/so-repo-sync
    - preserve: True

# This section is used to put the new script in place so that it can be called during soup.
# It is faster than calling the states that normally manage them to put them in place.
copy_so-common_sbin:
  file.copy:
    - name: /usr/sbin/so-common
    - source: {{UPDATE_DIR}}/salt/common/tools/sbin/so-common
    - force: True
    - preserve: True

copy_so-image-common_sbin:
  file.copy:
    - name: /usr/sbin/so-image-common
    - source: {{UPDATE_DIR}}/salt/common/tools/sbin/so-image-common
    - force: True
    - preserve: True

copy_soup_sbin:
  file.copy:
    - name: /usr/sbin/soup
    - source: {{UPDATE_DIR}}/salt/manager/tools/sbin/soup
    - force: True
    - preserve: True

copy_so-firewall_sbin:
  file.copy:
    - name: /usr/sbin/so-firewall
    - source: {{UPDATE_DIR}}/salt/manager/tools/sbin/so-firewall
    - force: True
    - preserve: True

copy_so-yaml_sbin:
  file.copy:
    - name: /usr/sbin/so-yaml.py
    - source: {{UPDATE_DIR}}/salt/manager/tools/sbin/so-yaml.py
    - force: True
    - preserve: True

copy_so-repo-sync_sbin:
  file.copy:
    - name: /usr/sbin/so-repo-sync
    - source: {{UPDATE_DIR}}/salt/manager/tools/sbin/so-repo-sync
    - force: True
    - preserve: True

{% else %}
fix_23_soup_sbin:
  cmd.run:
    - name: curl -s -f -o /usr/sbin/soup https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.3/main/salt/common/tools/sbin/soup
fix_23_soup_salt:
  cmd.run:
    - name: curl -s -f -o /opt/so/saltstack/defalt/salt/common/tools/sbin/soup https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/2.3/main/salt/common/tools/sbin/soup
{% endif %}
