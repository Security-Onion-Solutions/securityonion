{% if grains['os'] != 'CentOS' %}     
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
      - createrepo
      - python3-lxml
      - python3-packaging
      - yum-utils
      - device-mapper-persistent-data
      - lvm2
      - openssl
      - git
      - vim-enhanced
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
      - yum-utils
      - device-mapper-persistent-data
      - lvm2
      - openssl
      - git
      - vim-enhanced
      - yum-plugin-versionlock

{% endif %}