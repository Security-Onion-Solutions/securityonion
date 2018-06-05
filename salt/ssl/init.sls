{% set master = salt['grains.get']('master') %}
# Trust the CA
/usr/local/share/ca-certificates:
  file.directory: []

/usr/local/share/ca-certificates/intca.crt:
  x509.pem_managed:
    - text:  {{ salt['mine.get'](master, 'x509.get_pem_entries')[master]['/etc/pki/ca.crt']|replace('\n', '') }}

{% if grains['role'] == 'so-master' %}
# Request a cert and drop it where it needs to go to be distributed
/etc/pki/filebeat.crt:
  x509.certificate_managed:
    - ca_server: {{ master }}
    - signing_policy: filebeat
    - public_key: /etc/pki/filebeat.key
    - CN: ca.example.com
    - days_remaining: 3000
    - backup: True
    - managed_private_key:
        name: /etc/pki/filebeat.key
        bits: 4096
        backup: True

# Create Symlinks to the keys so I can distribute it to all the things

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
    - signing_policy: filebeat
    - public_key: /etc/pki/registry.key
    - CN: ca.example.com
    - days_remaining: 3000
    - backup: True
    - managed_private_key:
        name: /etc/pki/registry.key
        bits: 4096
        backup: True

{% endif %}