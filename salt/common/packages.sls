# we cannot import GLOBALS from vars/globals.map.jinja in this state since it is called in setup.virt.init
# since it is early in setup of a new VM, the pillars imported in GLOBALS are not yet defined

remove_mariadb:
  pkg.removed:
    - name: mariadb-devel

commonpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - python3-dnf-plugin-versionlock
      - bc
      - curl
      - device-mapper-persistent-data
      - fuse
      - fuse-libs
      - fuse-overlayfs
      - fuse-common
      - fuse3
      - fuse3-libs
      - git
      - httpd-tools
      - jq
      - lvm2
      - net-tools
      - nmap-ncat
      - procps-ng
      - python3-docker
      - python3-m2crypto
      - python3-packaging
      - python3-pyyaml
      - python3-rich
      - rsync
      - sqlite
      - tcpdump
      - unzip
      - wget
      - yum-utils
