{% from 'vars/globals.map.jinja' import GLOBALS %}

{% if GLOBALS.os == 'Ubuntu' %}
commonpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - apache2-utils
      - wget
      - ntpdate
      - jq
      - curl
      - ca-certificates
      - software-properties-common
      - apt-transport-https
      - openssl
      - netcat
      - sqlite3
      - libssl-dev
      - python3-dateutil
      - python3-packaging
      - python3-watchdog
      - python3-lxml
      - git
      - vim

# since Ubuntu requires and internet connection we can use pip to install modules
python3-pip:
  pkg.installed

python-rich:
  pip.installed:
    - name: rich
    - target: /usr/local/lib/python3.8/dist-packages/
    - require:
      - pkg: python3-pip
  

{% elif GLOBALS.os == 'Rocky' %}     
commonpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - wget
      - jq
      - tcpdump
      - httpd-tools
      - net-tools
      - curl
      - sqlite
      - mariadb-devel
      - python3-dnf-plugin-versionlock
      - nmap-ncat
      - yum-utils
      - device-mapper-persistent-data
      - lvm2
      - openssl
      - git
      - python3-docker
      - python3-m2crypto
      - rsync
      - python3-rich
      - python3-pyyaml
      - python3-watchdog
      - python3-packaging
      - unzip
      - fuse3
      - fuse-overlayfs
      - fuse3-libs
{% endif %}
