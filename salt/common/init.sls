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


# Install packages needed for the sensor
sensorpkgs:
  pkg.installed:
    - skip_suggestions: False
    - pkgs:
      - wget
      - jq
      {% if grains['os'] != 'CentOS' %}
      - apache2-utils
      {% else %}
      - net-tools
      - tcpdump
      - httpd-tools
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

# Sync some Utilities
utilsyncscripts:
  file.recurse:
    - name: /usr/sbin
    - user: 0
    - group: 0
    - file_mode: 755
    - template: jinja
    - source: salt://common/tools/sbin