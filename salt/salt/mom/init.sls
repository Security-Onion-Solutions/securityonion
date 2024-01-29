# from the local file_root (/opt/so/saltstack/local), 
local_nodegroups_state_directory:
  file.recurse:
    - name: /opt/so/saltstack/local/nodegroups/salt
    - user: 939
    - group: 939
    - source: salt://salt/
    - saltenv: local
    - makedirs: True

local_nodegroups_pillar_directory:
  file.recurse:
    - name: /opt/so/saltstack/local/nodegroups/pillar
    - user: 939
    - group: 939
    - source: salt://pillar/
    - saltenv: local
