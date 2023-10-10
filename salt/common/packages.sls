{% from 'vars/globals.map.jinja' import GLOBALS %}

{% if GLOBALS.os_family == 'Debian' %}
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
      - netcat-openbsd
      - sqlite3
      - libssl-dev
      - procps
      - python3-dateutil
      - python3-docker
      - python3-packaging
      - python3-lxml
      - git
      - rsync
      - vim
      - tar
      - unzip
      {% if grains.oscodename != 'focal' %}
      - python3-rich
      {% endif %}

{%     if grains.oscodename == 'focal' %}
# since Ubuntu requires and internet connection we can use pip to install modules
python3-pip:
  pkg.installed

python-rich:
  pip.installed:
    - name: rich
    - target: /usr/local/lib/python3.8/dist-packages/
    - require:
      - pkg: python3-pip
{%     endif %}
{% endif %}

{% if GLOBALS.os_family == 'RedHat' %}

remove_mariadb:
  pkg.removed:
    - name: mariadb-devel

commonpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - python3-dnf-plugin-versionlock
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

{% endif %}
