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

# install versionlock first so we can hold packages in the next states
install_versionlock:
  pkg.installed:
    - name: python3-dnf-plugin-versionlock

# holding these since openssl-devel-1:3.0.7-16.0.1.el9_2 seems to be a requirement for mariadb-devel-3:10.5.16-2.el9_0
# https://github.com/Security-Onion-Solutions/securityonion/discussions/11443
holdversion_openssl:
  pkg.held:
    - name: openssl
    - version: 1:3.0.7-16.0.1.el9_2

holdversion_openssl-libs:
  pkg.held:
    - name: openssl-libs
    - version: 1:3.0.7-16.0.1.el9_2

commonpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
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
      - openssl: 1:3.0.7-16.0.1.el9_2
      - openssl-libs: 1:3.0.7-16.0.1.el9_2
      - mariadb-devel
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
