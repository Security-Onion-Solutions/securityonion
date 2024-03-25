{% import_yaml '/opt/so/saltstack/local/pillar/global/soc_global.sls' as SOC_GLOBAL %}
{% if SOC_GLOBAL.global.airgap %}
{%   set UPDATE_DIR='/tmp/soagupdate/SecurityOnion' %}
{% else %}
{%   set UPDATE_DIR='/tmp/sogh/securityonion' %}
{% endif %}

remove_common_soup:
  file.absent:
    - name: /opt/so/saltstack/default/salt/common/tools/sbin/soup

remove_common_so-firewall:
  file.absent:
    - name: /opt/so/saltstack/default/salt/common/tools/sbin/so-firewall

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
