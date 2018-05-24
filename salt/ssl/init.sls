# Trust the CA
/usr/local/share/ca-certificates:
  file.directory: []

/usr/local/share/ca-certificates/intca.crt:
  x509.pem_managed:
    - text: {{ salt['mine.get']('ca', 'x509.get_pem_entries')['ca']['/etc/pki/ca.crt']|replace('\n', '') }}

# Request a cert and drop it where it needs to go to be distributed
/etc/pki/filebeat.crt:
  x509.certificate_managed:
    - ca_server: ca
    - signing_policy: filebeat
    - public_key: /etc/pki/filebeat.key
    - CN: security.onion
    - days_remaining: 3000
    - backup: True
    - managed_private_key:
        name: /etc/pki/filebeat.key
        bits: 4096
        backup: True

# Create Symlinks to the keys so I can distribute it to all the things