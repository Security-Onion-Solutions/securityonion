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
      - python3-lxml
      - python3-packaging
      - device-mapper-persistent-data
      - lvm2
      - openssl
      - git
      - python3-docker
{% else %}
commonpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - wget
      - ntpdate
      - bind-utils
      - jq
      - tcpdump
      - httpd-tools
      - net-tools
      - curl
      - sqlite
      - mariadb-devel
      - nmap-ncat
      - python3
      - python36-packaging
      - python36-lxml
      - python36-docker
      - python36-dateutil
      - python36-m2crypto
      - python36-mysql
      - python36-packaging
      - python36-lxml
      - securityonion-python36-watchdog
      - yum-utils
      - device-mapper-persistent-data
      - lvm2
      - openssl
      - git
      - vim-enhanced
      - yum-plugin-versionlock
{% endif %}
