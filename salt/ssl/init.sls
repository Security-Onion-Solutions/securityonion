{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set manager = salt['grains.get']('master') %}
{% set managerip = salt['pillar.get']('global:managerip', '') %}
{% set HOSTNAME = salt['grains.get']('host') %}
{% set global_ca_text = [] %}
{% set global_ca_server = [] %}
{% set MAININT = salt['pillar.get']('host:mainint') %}
{% set MAINIP = salt['grains.get']('ip_interfaces').get(MAININT)[0] %}
{% set CUSTOM_FLEET_HOSTNAME = salt['pillar.get']('global:fleet_custom_hostname', None) %}

{% if grains.id.split('_')|last in ['manager', 'eval', 'standalone', 'import', 'helixsensor'] %}
    {% set trusttheca_text = salt['cp.get_file_str']('/etc/pki/ca.crt')|replace('\n', '') %}
    {% set ca_server = grains.id %}
{% else %}
    {% set x509dict = salt['mine.get']('*', 'x509.get_pem_entries') %}
    {% for host in x509dict %}
      {% if 'manager' in host.split('_')|last or host.split('_')|last == 'standalone' %}
        {% do global_ca_text.append(x509dict[host].get('/etc/pki/ca.crt')|replace('\n', '')) %}
        {% do global_ca_server.append(host) %}
      {% endif %}
    {% endfor %}
    {% set trusttheca_text = global_ca_text[0] %}
    {% set ca_server = global_ca_server[0] %}
{% endif %}

# Trust the CA
trusttheca:
  x509.pem_managed:
    - name: /etc/ssl/certs/intca.crt
    - text:  {{ trusttheca_text }}

{% if grains['os'] != 'CentOS' %}
# Install packages needed for the sensor
m2cryptopkgs:
  pkg.installed:
    - skip_suggestions: False
    - pkgs:
      - python-m2crypto
{% endif %}

removefbcertdir:
  file.absent:
    - name: /etc/pki/filebeat.crt 
    - onlyif: "[ -d /etc/pki/filebeat.crt ]"

removefbp8dir:
  file.absent:
    - name: /etc/pki/filebeat.p8 
    - onlyif: "[ -d /etc/pki/filebeat.p8 ]"

removeesp12dir:
  file.absent:
    - name: /etc/pki/elasticsearch.p12
    - onlyif: "[ -d /etc/pki/elasticsearch.p12 ]"
    
/etc/pki/influxdb.key:
  x509.private_key_managed:
    - CN: {{ manager }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/influxdb.key') -%}
    - prereq:
      - x509: /etc/pki/influxdb.crt
    {%- endif %}
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

# Create a cert for the talking to influxdb
/etc/pki/influxdb.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: influxdb
    - public_key: /etc/pki/influxdb.key
    - CN: {{ manager }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /etc/pki/influxdb.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

influxkeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/influxdb.key
    - mode: 640
    - group: 939

{% if grains['role'] in ['so-manager', 'so-eval', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode', 'so-fleet'] %}
# Create a cert for Redis encryption
/etc/pki/redis.key:
  x509.private_key_managed:
    - CN: {{ manager }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/redis.key') -%}
    - prereq:
      - x509: /etc/pki/redis.crt
    {%- endif %}
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

/etc/pki/redis.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: registry
    - public_key: /etc/pki/redis.key
    - CN: {{ manager }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /etc/pki/redis.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

rediskeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/redis.key
    - mode: 640
    - group: 939
{% endif %}

{% if grains['role'] in ['so-manager', 'so-eval', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode'] %}
/etc/pki/filebeat.key:
  x509.private_key_managed:
    - CN: {{ manager }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/filebeat.key') -%}
    - prereq:
      - x509: /etc/pki/filebeat.crt
    {%- endif %}
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

# Request a cert and drop it where it needs to go to be distributed
/etc/pki/filebeat.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: filebeat
    - public_key: /etc/pki/filebeat.key
{% if grains.role == 'so-heavynode' %}
    - CN: {{grains.host}}
{% else %}
    - CN: {{manager}}
{% endif %}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /etc/pki/filebeat.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
  cmd.run:
    - name: "/usr/bin/openssl pkcs8 -in /etc/pki/filebeat.key -topk8 -out /etc/pki/filebeat.p8 -nocrypt"
    - onchanges:
      - x509: /etc/pki/filebeat.key


fbperms:
  file.managed:
    - replace: False
    - name: /etc/pki/filebeat.key
    - mode: 640
    - group: 939

chownilogstashfilebeatp8:
  file.managed:
    - replace: False
    - name: /etc/pki/filebeat.p8
    - mode: 640
    - user: 931
    - group: 939

  {% if grains.role != 'so-heavynode' %}
# Create Symlinks to the keys so I can distribute it to all the things
filebeatdir:
  file.directory:
    - name: /opt/so/saltstack/local/salt/filebeat/files
    - makedirs: True

fbkeylink:
  file.symlink:
    - name: /opt/so/saltstack/local/salt/filebeat/files/filebeat.p8
    - target: /etc/pki/filebeat.p8
    - user: socore
    - group: socore

fbcrtlink:
  file.symlink:
    - name: /opt/so/saltstack/local/salt/filebeat/files/filebeat.crt
    - target: /etc/pki/filebeat.crt
    - user: socore
    - group: socore

/etc/pki/registry.key:
  x509.private_key_managed:
    - CN: {{ manager }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/registry.key') -%}
    - prereq:
      - x509: /etc/pki/registry.crt
    {%- endif %}
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

# Create a cert for the docker registry
/etc/pki/registry.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: registry
    - public_key: /etc/pki/registry.key
    - CN: {{ manager }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /etc/pki/registry.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

regkeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/registry.key
    - mode: 640
    - group: 939

/etc/pki/minio.key:
  x509.private_key_managed:
    - CN: {{ manager }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/minio.key') -%}
    - prereq:
      - x509: /etc/pki/minio.crt
    {%- endif %}
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

# Create a cert for minio
/etc/pki/minio.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: registry
    - public_key: /etc/pki/minio.key
    - CN: {{ manager }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /etc/pki/minio.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

miniokeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/minio.key
    - mode: 640
    - group: 939
  {% endif %}
# Create a cert for elasticsearch
/etc/pki/elasticsearch.key:
  x509.private_key_managed:
    - CN: {{ manager }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/elasticsearch.key') -%}
    - prereq:
      - x509: /etc/pki/elasticsearch.crt
    {%- endif %}
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

/etc/pki/elasticsearch.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: registry
    - public_key: /etc/pki/elasticsearch.key
    - CN: {{ manager }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /etc/pki/elasticsearch.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
  cmd.run:
    - name: "/usr/bin/openssl pkcs12 -inkey /etc/pki/elasticsearch.key -in /etc/pki/elasticsearch.crt -export -out /etc/pki/elasticsearch.p12 -nodes -passout pass:"
    - onchanges:
      - x509: /etc/pki/elasticsearch.key

ealstickeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticsearch.key
    - mode: 640
    - group: 930
    
elasticp12perms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticsearch.p12
    - mode: 640
    - group: 930

/etc/pki/managerssl.key:
  x509.private_key_managed:
    - CN: {{ manager }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/managerssl.key') -%}
    - prereq:
      - x509: /etc/pki/managerssl.crt
    {%- endif %}
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

# Create a cert for the reverse proxy
/etc/pki/managerssl.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: managerssl
    - public_key: /etc/pki/managerssl.key
    - CN: {{ manager }}
    - subjectAltName: DNS:{{ HOSTNAME }}, IP:{{ MAINIP }} {% if CUSTOM_FLEET_HOSTNAME != None %},DNS:{{ CUSTOM_FLEET_HOSTNAME }} {% endif %}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /etc/pki/managerssl.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

msslkeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/managerssl.key
    - mode: 640
    - group: 939

# Create a private key and cert for OSQuery
/etc/pki/fleet.key:
  x509.private_key_managed:
    - CN: {{ manager }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/fleet.key') -%}
    - prereq:
      - x509: /etc/pki/fleet.crt
    {%- endif %}
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

/etc/pki/fleet.crt:
  x509.certificate_managed:
    - signing_private_key: /etc/pki/fleet.key
    - CN: {{ manager }}
    - subjectAltName: DNS:{{ manager }},IP:{{ managerip }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /etc/pki/fleet.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

fleetkeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/fleet.key
    - mode: 640
    - group: 939

{% endif %}
{% if grains['role'] in ['so-sensor', 'so-manager', 'so-node', 'so-eval', 'so-helix', 'so-managersearch', 'so-heavynode', 'so-fleet', 'so-standalone', 'so-import'] %}
   
fbcertdir:
  file.directory:
    - name: /opt/so/conf/filebeat/etc/pki
    - makedirs: True

/opt/so/conf/filebeat/etc/pki/filebeat.key:
  x509.private_key_managed:
    - CN: {{ manager }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/opt/so/conf/filebeat/etc/pki/filebeat.key') -%}
    - prereq:
      - x509: /opt/so/conf/filebeat/etc/pki/filebeat.crt
    {%- endif %}
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

# Request a cert and drop it where it needs to go to be distributed
/opt/so/conf/filebeat/etc/pki/filebeat.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: filebeat
    - public_key: /opt/so/conf/filebeat/etc/pki/filebeat.key
{% if grains.role == 'so-heavynode' %}
    - CN: {{grains.id}}
{% else %}
    - CN: {{manager}}
{% endif %}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /opt/so/conf/filebeat/etc/pki/filebeat.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

# Convert the key to pkcs#8 so logstash will work correctly.
filebeatpkcs:
  cmd.run:
    - name: "/usr/bin/openssl pkcs8 -in /opt/so/conf/filebeat/etc/pki/filebeat.key -topk8 -out /opt/so/conf/filebeat/etc/pki/filebeat.p8 -passout pass:"
    - onchanges:
      - x509: /opt/so/conf/filebeat/etc/pki/filebeat.key

filebeatkeyperms:
  file.managed:
    - replace: False
    - name: /opt/so/conf/filebeat/etc/pki/filebeat.key
    - mode: 640
    - group: 939

chownfilebeatp8:
  file.managed:
    - replace: False
    - name: /opt/so/conf/filebeat/etc/pki/filebeat.p8
    - mode: 640
    - user: 931
    - group: 939
    
{% endif %}

{% if grains['role'] == 'so-fleet' %}

/etc/pki/managerssl.key:
  x509.private_key_managed:
    - CN: {{ manager }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/managerssl.key') -%}
    - prereq:
      - x509: /etc/pki/managerssl.crt
    {%- endif %}
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

# Create a cert for the reverse proxy
/etc/pki/managerssl.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: managerssl
    - public_key: /etc/pki/managerssl.key
    - CN: {{ HOSTNAME }}
    - subjectAltName: DNS:{{ HOSTNAME }}, IP:{{ MAINIP }} {% if CUSTOM_FLEET_HOSTNAME != None %},DNS:{{ CUSTOM_FLEET_HOSTNAME }} {% endif %}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /etc/pki/managerssl.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

msslkeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/managerssl.key
    - mode: 640
    - group: 939

# Create a private key and cert for Fleet
/etc/pki/fleet.key:
  x509.private_key_managed:
    - CN: {{ manager }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/fleet.key') -%}
    - prereq:
      - x509: /etc/pki/fleet.crt
    {%- endif %}
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

/etc/pki/fleet.crt:
  x509.certificate_managed:
    - signing_private_key: /etc/pki/fleet.key
    - CN: {{ HOSTNAME }}
    - subjectAltName: DNS:{{ HOSTNAME }}, IP:{{ MAINIP }} {% if CUSTOM_FLEET_HOSTNAME != None %},DNS:{{ CUSTOM_FLEET_HOSTNAME }} {% endif %}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /etc/pki/fleet.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

fleetkeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/fleet.key
    - mode: 640
    - group: 939

{% endif %}

{% if grains['role'] == 'so-node' %}
# Create a cert for elasticsearch
/etc/pki/elasticsearch.key:
  x509.private_key_managed:
    - CN: {{ manager }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/elasticsearch.key') -%}
    - prereq:
      - x509: /etc/pki/elasticsearch.crt
    {%- endif %}
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

/etc/pki/elasticsearch.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: registry
    - public_key: /etc/pki/elasticsearch.key
    - CN: {{ HOSTNAME }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /etc/pki/elasticsearch.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
  cmd.run:
    - name: "/usr/bin/openssl pkcs12 -inkey /etc/pki/elasticsearch.key -in /etc/pki/elasticsearch.crt -export -out /etc/pki/elasticsearch.p12 -nodes -passout pass:"
    - onchanges:
      - x509: /etc/pki/elasticsearch.key

elasticp12perms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticsearch.p12
    - mode: 640
    - group: 930
    
elastickeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticsearch.key
    - mode: 640
    - group: 930

{%- endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}