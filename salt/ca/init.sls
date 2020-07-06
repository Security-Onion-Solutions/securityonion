{% set master = salt['grains.get']('master') %}
/etc/salt/minion.d/signing_policies.conf:
  file.managed:
    - source: salt://ca/files/signing_policies.conf

/etc/pki:
  file.directory: []

/etc/pki/issued_certs:
  file.directory: []

pki_private_key:
    x509.private_key_managed:
        - name: /etc/pki/ca.key
        - bits: 4096
        - passphrase:
        - cipher: aes_256_cbc
        - backup: True

/etc/pki/ca.crt:
  x509.certificate_managed:
    - signing_private_key: /etc/pki/ca.key
    - CN: {{ master }}
    - C: US
    - ST: Utah
    - L: Salt Lake City
    - basicConstraints: "critical CA:true"
    - keyUsage: "critical cRLSign, keyCertSign"
    - extendedkeyUsage: "serverAuth, clientAuth"
    - subjectKeyIdentifier: hash
    - authorityKeyIdentifier: keyid,issuer:always
    - days_valid: 3650
    - days_remaining: 0
    - backup: True
    - managed_private_key:
        name: /etc/pki/ca.key
        bits: 4096
        backup: True
    - require:
      - file: /etc/pki

send_x509_pem_entries_to_mine:
  module.run:
    - mine.send:
      - func: x509.get_pem_entries
      - glob_path: /etc/pki/ca.crt

cakeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/ca.key
    - mode: 640
    - group: 939
