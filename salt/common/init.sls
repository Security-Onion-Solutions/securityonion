# Add socore Group
socoregroup:
  group.present:
    - name: socore
    - gid: 939

# Add socore user
socore:
  user.present:
    - uid: 939
    - gid: 939
    - home: /opt/so
    - createhome: True
    - shell: /bin/bash

# Create a state directory
statedir:
  file.directory:
    - name: /opt/so/state
    - user: 939
    - group: 939
    - makedirs: True

salttmp:
  file.directory:
    - name: /opt/so/tmp
    - user: 939
    - group: 939
    - makedirs: True

# Install epel
{% if grains['os'] == 'CentOS' %}
epel:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - epel-release
{% endif %}

# Install common packages
commonpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      {% if grains['os'] != 'CentOS' %}
      - apache2-utils
      - wget
      - jq
      - python3-docker
      - docker-ce
      - curl
      - ca-certificates
      - software-properties-common
      - apt-transport-https
      - openssl
      - netcat
      - python3-mysqldb
      - sqlite3
      - argon2
      - libssl-dev
      - python3-dateutil
      - python3-m2crypto
      - python3-mysqldb
      - salt-minion: 2019.2.5+ds-1
        - hold: True
        - update_holds: True
      {% if grains['role'] == 'so-master' or grains['role'] == 'so-eval' or grains['role'] == 'so-helix' or grains['role'] == 'so-mastersearch' or grains['role'] == 'so-standalone' %}
      - salt-master: 2019.2.5+ds-1
        - hold: True
        - update_holds: True
      - containerd.io: 1.2.13-2
        - hold: True
        - update_holds: True
      - docker-ce: 5:19.03.9~3-0~ubuntu-bionic
        - hold: True
        - update_holds: True
      {% endif %}
      - containerd.io
      - docker-ce      
      {% else %}
      - wget
      - bind-utils
      - jq
      - tcpdump
      - httpd-tools
      - net-tools
      - curl
      - sqlite
      - argon2
      - maridb-devel
      - nmap-ncat
      - python3
			-	python36-docker
			-	python36-dateutil
			-	python36-m2crypto
			-	python36-mysql
			-	yum-utils
			-	device-mapper-persistent-data
			-	lvm2
			-	openssl
      - salt-minion: 2019.2.5.el7
        - hold: True
        - update_holds: True
      {% if grains['role'] == 'so-master' or grains['role'] == 'so-eval' or grains['role'] == 'so-helix' or grains['role'] == 'so-mastersearch' or grains['role'] == 'so-standalone' %}
      - salt-master: 2019.2.5.el7
        - hold: True
        - update_holds: True
      {% endif %}
      - containerd.io: 1.2.6-3.el7
        - hold: True
        - update_holds: True
      - docker-ce: 19.03.9-3.el7
        - hold: True
        - update_holds: True
      {% endif %}%}
				
# Always keep these packages up to date

alwaysupdated:
  pkg.latest:
    - pkgs:
      - openssl
      - openssh-server
      - bash
    - skip_suggestions: True

# Set time to UTC
Etc/UTC:
  timezone.system

# Sync some Utilities
utilsyncscripts:
  file.recurse:
    - name: /usr/sbin
    - user: 0
    - group: 0
    - file_mode: 755
    - template: jinja
    - source: salt://common/tools/sbin