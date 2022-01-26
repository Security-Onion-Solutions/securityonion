pki_private_key:
  file.absent:
    - name: /etc/pki/ca.key

pki_public_ca_crt:
  file.absent:
    - name: /etc/pki/ca.crt

remove_ca-certificates.crt:
  file.absent:
    - name: /etc/ssl/certs/ca-certificates.crt
