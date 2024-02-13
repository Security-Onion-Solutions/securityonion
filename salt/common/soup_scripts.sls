remove_common_soup:
  file.absent:
    - name: /opt/so/saltstack/default/salt/common/tools/sbin/soup

remove_common_so-firewall:
  file.absent:
    - name: /opt/so/saltstack/default/salt/common/tools/sbin/so-firewall

# Sync some Utilities
soup_scripts:
  file.recurse:
    - name: /usr/sbin
    - user: root
    - group: root
    - file_mode: 755
    - source: salt://common/tools/sbin

soup_manager_scripts:
  file.recurse:
    - name: /usr/sbin
    - user: root
    - group: root
    - file_mode: 755
    - source: salt://manager/tools/sbin
