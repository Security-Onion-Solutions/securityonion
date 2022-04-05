ubuntu_repo_files:
  - file.recurse:
      - name: /etc/apt/sources.list.d/
      - source: salt://repo/client/files/ubuntu/{{grains.osrelease}}/
