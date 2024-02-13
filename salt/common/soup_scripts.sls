remove_common_soup:
  file.absent:
    - name: /opt/so/saltstack/default/salt/common/tools/sbin/soup

remove_common_so-firewall:
  file.absent:
    - name: /opt/so/saltstack/default/salt/common/tools/sbin/so-firewall

{% if salt['pillar.get']('global:airgap') %}
{%   set UPDATE_DIR='/tmp/soagupdate/SecurityOnion'%}
{% else %}
{%   set UPDATE_DIR='/tmp/sogh/securityonion'%}
{% endif %}

copy_common:
  cmd.run:
    - name: "cp {{UPDATE_DIR}}/salt/common/tools/sbin/* /usr/sbin/."

copy_manager:
  cmd.run:
    - name: "cp {{UPDATE_DIR}}/salt/manager/tools/sbin/* /usr/sbin/."
