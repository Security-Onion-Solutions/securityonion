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
      - python3-dateutil
      - python3-docker
      - python3-packaging
      - python3-watchdog
      - python3-lxml
      - git
      - rsync
      - vim
      - tar
      - unzip
      {% if grains.oscodename != 'focal' %}
      - python3-rich
      {% endif %}

{% if grains.oscodename == 'focal' %}
# since Ubuntu requires and internet connection we can use pip to install modules
python3-pip:
  pkg.installed

python-rich:
  pip.installed:
    - name: rich
    - target: /usr/local/lib/python3.8/dist-packages/
    - require:
      - pkg: python3-pip
{% endif %}

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

{% elif GLOBALS.os == 'CentOS Stream' %}     
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
      - MariaDB-devel
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
      - python3-packaging
      - unzip
      - fuse
      - fuse-libs
      - fuse-overlayfs
      - fuse-common
{% endif %}
