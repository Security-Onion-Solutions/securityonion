{% from 'vars/globals.map.jinja' import GLOBALS %}

{% if GLOBALS.os == 'Ubuntu' %}
commonpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - chrony
      - apache2-utils
      - wget
      - ntpdate
      - jq
      - python3-docker
      - curl
      - ca-certificates
      - software-properties-common
      - apt-transport-https
      - openssl
      - netcat
      - python3-mysqldb
      - sqlite3
      - libssl-dev
      - python3-dateutil
      - python3-m2crypto
      - python3-mysqldb
      - python3-packaging
      - python3-lxml
      - git
      - vim
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
      - python3-watchdog
      - unzip
{% endif %}
