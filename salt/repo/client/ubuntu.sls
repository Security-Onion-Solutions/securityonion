saltstack.list:
  file.managed:
    - name: /etc/apt/sources.list.d/saltstack.list
    - contents:
      - deb https://repo.securityonion.net/file/securityonion-repo/ubuntu/{{grains.osrelease}}/amd64/salt/ {{grains.oscodename}} main
