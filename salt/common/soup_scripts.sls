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

copy_common_tools_sbin:
  cmd.run:
    - name: "rsync -avh {{UPDATE_DIR}}/salt/common/tools/sbin/* /opt/so/saltstack/default/salt/common/tools/sbin/"

copy_manager_tools_sbin:
  cmd.run:
    - name: "rsync -avh {{UPDATE_DIR}}/salt/manager/tools/sbin/* /opt/so/saltstack/default/salt/manager/tools/sbin/"

copy_common_sbin:
  cmd.run:
    - name: "rsync -avh {{UPDATE_DIR}}/salt/common/tools/sbin/* /usr/sbin/"

copy_manager_sbin:
  cmd.run:
    - name: "rsync -avh {{UPDATE_DIR}}/salt/manager/tools/sbin/* /usr/sbin/"
