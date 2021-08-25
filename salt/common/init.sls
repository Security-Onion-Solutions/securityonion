{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set role = grains.id.split('_') | last %}
{% from 'elasticsearch/auth.map.jinja' import ELASTICAUTH with context %}

# Remove variables.txt from /tmp - This is temp
rmvariablesfile:
  file.absent:
    - name: /tmp/variables.txt

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

soconfperms:
  file.directory:
    - name: /opt/so/conf
    - uid: 939
    - gid: 939
    - dir_mode: 770

sostatusconf:
  file.directory:
    - name: /opt/so/conf/so-status
    - uid: 939
    - gid: 939
    - dir_mode: 770

so-status.conf:
  file.touch:
    - name: /opt/so/conf/so-status/so-status.conf
    - unless: ls /opt/so/conf/so-status/so-status.conf

sosaltstackperms:
  file.directory:
    - name: /opt/so/saltstack
    - uid: 939
    - gid: 939
    - dir_mode: 770

so_log_perms:
  file.directory:
    - name: /opt/so/log
    - dir_mode: 755

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

# VIM config
vimconfig:
  file.managed:
    - name: /root/.vimrc
    - source: salt://common/files/vimrc
    - replace: False

# Install common packages
{% if grains['os'] != 'CentOS' %}     
commonpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
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
      - git
      - vim

heldpackages:
  pkg.installed:
    - pkgs:
      - containerd.io: 1.4.9-1
      - docker-ce: 5:20.10.8~3-0~ubuntu-focal
      - docker-ce-cli: 5:20.10.5~3-0~ubuntu-focal
      - docker-ce-rootless-extras: 5:20.10.5~3-0~ubuntu-focal
    - hold: True
    - update_holds: True

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
      - python36-docker
      - python36-dateutil
      - python36-m2crypto
      - python36-mysql
      - python36-packaging
      - yum-utils
      - device-mapper-persistent-data
      - lvm2
      - openssl
      - git
      - vim-enhanced

heldpackages:
  pkg.installed:
    - pkgs:
      - containerd.io: 1.4.4-3.1.el7
      - docker-ce: 3:20.10.5-3.el7
      - docker-ce-cli: 1:20.10.5-3.el7
      - docker-ce-rootless-extras: 20.10.5-3.el7
    - hold: True
    - update_holds: True
{% endif %}

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

elastic_curl_config:
  file.managed:
    - name: /opt/so/conf/elasticsearch/curl.config
    - source: salt://elasticsearch/curl.config
    - mode: 600
    - show_changes: False
    - makedirs: True

# Sync some Utilities
utilsyncscripts:
  file.recurse:
    - name: /usr/sbin
    - user: root
    - group: root
    - file_mode: 755
    - template: jinja
    - source: salt://common/tools/sbin
    - defaults:
        ELASTICCURL: 'curl'
    - context:
        ELASTICCURL: {{ ELASTICAUTH.elasticcurl }}

{% if role in ['eval', 'standalone', 'sensor', 'heavynode'] %}
# Add sensor cleanup
/usr/sbin/so-sensor-clean:
  cron.present:
    - user: root
    - minute: '*'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

sensorrotatescript:
  file.managed:
    - name: /usr/local/bin/sensor-rotate
    - source: salt://common/cron/sensor-rotate
    - mode: 755

sensorrotateconf:
  file.managed:
    - name: /opt/so/conf/sensor-rotate.conf
    - source: salt://common/files/sensor-rotate.conf
    - mode: 644

/usr/local/bin/sensor-rotate:
  cron.present:
    - user: root
    - minute: '1'
    - hour: '0'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

{% endif %}

commonlogrotatescript:
  file.managed:
    - name: /usr/local/bin/common-rotate
    - source: salt://common/cron/common-rotate
    - mode: 755

commonlogrotateconf:
  file.managed:
    - name: /opt/so/conf/log-rotate.conf
    - source: salt://common/files/log-rotate.conf
    - template: jinja
    - mode: 644

/usr/local/bin/common-rotate:
  cron.present:
    - user: root
    - minute: '1'
    - hour: '0'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

# Create the status directory
sostatusdir:
  file.directory:
    - name: /opt/so/log/sostatus
    - user: 0
    - group: 0
    - makedirs: True

sostatus_log:
  file.managed:
    - name: /opt/so/log/sostatus/status.log
    - mode: 644
    
# Install sostatus check cron
'/usr/sbin/so-status -q; echo $? > /opt/so/log/sostatus/status.log 2>&1':
  cron.present:
    - user: root
    - minute: '*/1'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'


{% if role in ['eval', 'manager', 'managersearch', 'standalone'] %}
# Lock permissions on the backup directory
backupdir:
  file.directory:
    - name: /nsm/backup
    - user: 0
    - group: 0
    - makedirs: True
    - mode: 700
  
# Add config backup
/usr/sbin/so-config-backup > /dev/null 2>&1:
  cron.present:
    - user: root
    - minute: '1'
    - hour: '0'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'
{% else %}
soversionfile:
  file.managed:
    - name: /etc/soversion
    - source: salt://common/files/soversion
    - mode: 644
    - template: jinja
    
{% endif %}

# Manager daemon.json
docker_daemon:
  file.managed:
    - source: salt://common/files/daemon.json
    - name: /etc/docker/daemon.json
    - template: jinja 

# Make sure Docker is always running
docker:
  service.running:
    - enable: True
    - watch:
      - file: docker_daemon

# Reserve OS ports for Docker proxy in case boot settings are not already applied/present
# 55000 = Wazuh, 57314 = Strelka, 47760-47860 = Zeek
dockerapplyports:
    cmd.run:
      - name: if [ ! -s /etc/sysctl.d/99-reserved-ports.conf ]; then sysctl -w net.ipv4.ip_local_reserved_ports="55000,57314,47760-47860"; fi

# Reserve OS ports for Docker proxy
dockerreserveports:
  file.managed:
    - source: salt://common/files/99-reserved-ports.conf
    - name: /etc/sysctl.d/99-reserved-ports.conf

{% if salt['grains.get']('sosmodel', '') %}
  {% if grains['os'] == 'CentOS' %}     
# Install Raid tools
raidpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - securityonion-raidtools
      - securityonion-megactl
  {% endif %}

# Install raid check cron
/usr/sbin/so-raid-status > /dev/null 2>&1:
  cron.present:
    - user: root
    - minute: '*/15'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
