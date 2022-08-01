# this removes the repo file left by bootstrap-salt.sh without -r
remove_salt.list:
  file.absent:
    - name: /etc/apt/sources.list.d/salt.list

saltstack.list:
  file.managed:
    - name: /etc/apt/sources.list.d/saltstack.list
    - contents:
      - deb https://repo.securityonion.net/file/securityonion-repo/ubuntu/{{grains.osrelease}}/amd64/salt3004.2/ {{grains.oscodename}} main

apt_update:
  cmd.run:
    - name: apt-get update
    - onchanges:
      - file: saltstack.list
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
