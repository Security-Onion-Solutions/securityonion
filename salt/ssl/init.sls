{% set master = salt['grains.get']('master') %}
{%- set masterip = salt['pillar.get']('static:masterip', '') -%}

# Trust the CA

trusttheca:
  x509.pem_managed:
    - name: /etc/ssl/certs/intca.crt
    - text:  {{ salt['mine.get'](master, 'x509.get_pem_entries')[master]['/etc/pki/ca.crt']|replace('\n', '') }}

# Install packages needed for the sensor
{% if grains['os'] != 'CentOS' %}
m2cryptopkgs:
  pkg.installed:
    - skip_suggestions: False
    - pkgs:
      - python-m2crypto
{% endif %}

# Create a cert for the talking to influxdb
/etc/pki/influxdb.crt:
  x509.certificate_managed:
    - ca_server: {{ master }}
    - signing_policy: influxdb
    - public_key: /etc/pki/influxdb.key
    - CN: {{ master }}
    - days_remaining: 0
    - days_valid: 3650
    - backup: True
    - managed_private_key:
        name: /etc/pki/influxdb.key
        bits: 4096
        backup: True

{% if grains['role'] == 'so-master' or grains['role'] == 'so-eval' %}

# Request a cert and drop it where it needs to go to be distributed
/etc/pki/filebeat.crt:
  x509.certificate_managed:
    - ca_server: {{ master }}
    - signing_policy: filebeat
    - public_key: /etc/pki/filebeat.key
    - CN: {{ master }}
    - days_remaining: 0
    - days_valid: 3650
    - backup: True
    - managed_private_key:
        name: /etc/pki/filebeat.key
        bits: 4096
        backup: True
  cmd.run:
    - name: "/usr/bin/openssl pkcs8 -in /etc/pki/filebeat.key -topk8 -out /etc/pki/filebeat.p8 -nocrypt"

# Create Symlinks to the keys so I can distribute it to all the things
filebeatdir:
  file.directory:
    - name: /opt/so/saltstack/salt/filebeat/files
    - mkdirs: True

fbkeylink:
  file.symlink:
    - name: /opt/so/saltstack/salt/filebeat/files/filebeat.p8
    - target: /etc/pki/filebeat.p8

fbcrtlink:
  file.symlink:
    - name: /opt/so/saltstack/salt/filebeat/files/filebeat.crt
    - target: /etc/pki/filebeat.crt

# Create a cert for the docker registry
/etc/pki/registry.crt:
  x509.certificate_managed:
    - ca_server: {{ master }}
    - signing_policy: registry
    - public_key: /etc/pki/registry.key
    - CN: {{ master }}
    - days_remaining: 0
    - days_valid: 3650
    - backup: True
    - managed_private_key:
        name: /etc/pki/registry.key
        bits: 4096
        backup: True

# Create a cert for the reverse proxy
/etc/pki/masterssl.crt:
  x509.certificate_managed:
    - ca_server: {{ master }}
    - signing_policy: masterssl
    - public_key: /etc/pki/masterssl.key
    - CN: {{ master }}
    - days_remaining: 0
    - days_valid: 3650
    - backup: True
    - managed_private_key:
        name: /etc/pki/masterssl.key
        bits: 4096
        backup: True

# Create a private key and cert for OSQuery
/etc/pki/fleet.key:
  x509.private_key_managed:
    - CN: {{ master }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 3650
    - backup: True

/etc/pki/fleet.crt:
  x509.certificate_managed:
    - signing_private_key: /etc/pki/fleet.key
    - CN: {{ master }}
    - subjectAltName: DNS:{{ master }},IP:{{ masterip }}
    - days_remaining: 0
    - days_valid: 3650
    - backup: True
    - managed_private_key:
        name: /etc/pki/fleet.key
        bits: 4096
        backup: True

{% endif %}
{% if grains['role'] == 'so-sensor' or grains['role'] == 'so-node' or grains['role'] == 'so-eval' %}

fbcertdir:
  file.directory:
    - name: /opt/so/conf/filebeat/etc/pki
    - makedirs: True

# Request a cert and drop it where it needs to go to be distributed
/opt/so/conf/filebeat/etc/pki/filebeat.crt:
  x509.certificate_managed:
    - ca_server: {{ master }}
    - signing_policy: filebeat
    - public_key: /opt/so/conf/filebeat/etc/pki/filebeat.key
    - CN: {{ master }}
    - days_remaining: 0
    - days_valid: 3650
    - backup: True
    - managed_private_key:
        name: /opt/so/conf/filebeat/etc/pki/filebeat.key
        bits: 4096
        backup: True

# Convert the key to pkcs#8 so logstash will work correctly.
filebeatpkcs:
  cmd.run:
    - name: "/usr/bin/openssl pkcs8 -in /opt/so/conf/filebeat/etc/pki/filebeat.key -topk8 -out /opt/so/conf/filebeat/etc/pki/filebeat.p8 -passout pass:"

{% endif %}
