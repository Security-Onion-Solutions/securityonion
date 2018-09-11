{% set master = salt['grains.get']('master') %}

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

{% if grains['role'] == 'so-master' %}
# Request a cert and drop it where it needs to go to be distributed
/etc/pki/filebeat.crt:
  x509.certificate_managed:
    - ca_server: {{ master }}
    - signing_policy: filebeat
    - public_key: /etc/pki/filebeat.key
    - CN: {{ master }}
    - days_remaining: 3000
    - backup: True
    - managed_private_key:
        name: /etc/pki/filebeat.key
        bits: 4096
        backup: True

# Create Symlinks to the keys so I can distribute it to all the things
filebeatdir:
  file.directory:
    - name: /opt/so/saltstack/salt/filebeat/files
    - mkdirs: True

fbkeylink:
  file.symlink:
    - name: /opt/so/saltstack/salt/filebeat/files/filebeat.key
    - target: /etc/pki/filebeat.key

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
    - days_remaining: 3000
    - backup: True
    - managed_private_key:
        name: /etc/pki/registry.key
        bits: 4096
        backup: True

{% endif %}
{% if grains['role'] == 'so-SENSOR' %}
# Request a cert and drop it where it needs to go to be distributed
/opt/so/conf/filebeat/etc/pki/filebeat.crt:
  x509.certificate_managed:
    - ca_server: {{ master }}
    - signing_policy: filebeat
    - public_key: /opt/so/conf/filebeat/etc/pki/filebeat.key
    - CN: {{ master }}
    - days_remaining: 3000
    - backup: True
    - managed_private_key:
        name: /opt/so/conf/filebeat/etc/pki/filebeat.key
        bits: 4096
        backup: True

{% endif %}
