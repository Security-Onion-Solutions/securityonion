# Trust the CA
/usr/local/share/ca-certificates:
  file.directory: []

/usr/local/share/ca-certificates/intca.crt:
  x509.pem_managed:
    - text: {{ salt['mine.get']('ca', 'x509.get_pem_entries')['ca']['/etc/pki/ca.crt']|replace('\n', '') }}

# Request a cert
/etc/pki/filebeat.crt:
  x509.certificate_managed:
    - ca_server: ca
    - signing_policy: filebeat
    - public_key: /etc/pki/filebeat.key
    - CN: www.example.com
    - days_remaining: 3000
    - backup: True
    - managed_private_key:
        name: /etc/pki/filebeat.key
        bits: 4096
        backup: True