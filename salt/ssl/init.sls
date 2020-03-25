{% set master = salt['grains.get']('master') %}
{% set masterip = salt['pillar.get']('static:masterip', '') %}
{% set HOSTNAME = salt['grains.get']('host') %}
{% set MAINIP = salt['pillar.get']('node:mainip') %}
{% set global_ca_text = [] %}
{% set global_ca_server = [] %}

{% if 'master' in grains.id.split('_')|last or 'eval' in grains.id.split('_')|last %}
    {% set trusttheca_text =  salt['mine.get'](grains.id, 'x509.get_pem_entries')[grains.id]['/etc/pki/ca.crt']|replace('\n', '') %}
    {% set ca_server = grains.id %}
{% else %}
    {% set x509dict =  salt['mine.get']('*', 'x509.get_pem_entries') %}
    {% for host in x509dict %}
      {% if 'master' in host.split('_')|last %}
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

# Create a cert for the talking to influxdb
/etc/pki/influxdb.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: influxdb
    - public_key: /etc/pki/influxdb.key
    - CN: {{ master }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - managed_private_key:
        name: /etc/pki/influxdb.key
        bits: 4096
        backup: True

{% if grains['role'] == 'so-master' or grains['role'] == 'so-eval' or grains['role'] == 'so-helix' or grains['role'] == 'so-mastersearch' %}

# Request a cert and drop it where it needs to go to be distributed
/etc/pki/filebeat.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: filebeat
    - public_key: /etc/pki/filebeat.key
{% if grains.role == 'so-heavynode' %}
    - CN: {{grains.id}}
{% else %}
    - CN: {{master}}
{% endif %}
    - days_remaining: 0
    - days_valid: 820
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
    - ca_server: {{ ca_server }}
    - signing_policy: registry
    - public_key: /etc/pki/registry.key
    - CN: {{ master }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - managed_private_key:
        name: /etc/pki/registry.key
        bits: 4096
        backup: True

# Create a cert for the reverse proxy
/etc/pki/masterssl.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: masterssl
    - public_key: /etc/pki/masterssl.key
    - CN: {{ master }}
    - days_remaining: 0
    - days_valid: 820
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
    - days_valid: 820
    - backup: True

/etc/pki/fleet.crt:
  x509.certificate_managed:
    - signing_private_key: /etc/pki/fleet.key
    - CN: {{ master }}
    - subjectAltName: DNS:{{ master }},IP:{{ masterip }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - managed_private_key:
        name: /etc/pki/fleet.key
        bits: 4096
        backup: True

{% endif %}
{% if grains['role'] == 'so-sensor' or grains['role'] == 'so-master' or grains['role'] == 'so-node' or grains['role'] == 'so-eval' or grains['role'] == 'so-helix' or grains['role'] == 'so-mastersearch' or grains['role'] == 'so-heavynode' %}

fbcertdir:
  file.directory:
    - name: /opt/so/conf/filebeat/etc/pki
    - makedirs: True

# Request a cert and drop it where it needs to go to be distributed
/opt/so/conf/filebeat/etc/pki/filebeat.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: filebeat
    - public_key: /opt/so/conf/filebeat/etc/pki/filebeat.key
{% if grains.role == 'so-heavynode' %}
    - CN: {{grains.id}}
{% else %}
    - CN: {{master}}
{% endif %}
    - days_remaining: 0
    - days_valid: 820
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

{% if grains['role'] == 'so-fleet' %}

# Create a cert for the reverse proxy
/etc/pki/masterssl.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: masterssl
    - public_key: /etc/pki/masterssl.key
    - CN: {{ HOSTNAME }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - managed_private_key:
        name: /etc/pki/masterssl.key
        bits: 4096
        backup: True


# Create a private key and cert for Fleet
/etc/pki/fleet.key:
  x509.private_key_managed:
    - CN: {{ HOSTNAME }}
    - bits: 4096
    - days_remaining: 0
    - days_valid: 820
    - backup: True

/etc/pki/fleet.crt:
  x509.certificate_managed:
    - signing_private_key: /etc/pki/fleet.key
    - CN: {{ HOSTNAME }}
    - subjectAltName: DNS:{{ HOSTNAME }}, IP:{{ MAINIP }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - managed_private_key:
        name: /etc/pki/fleet.key
        bits: 4096
        backup: True

{% endif %}
