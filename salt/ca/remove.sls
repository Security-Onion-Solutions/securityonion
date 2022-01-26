pki_private_key:
  file.absent:
    - name: /etc/pki/ca.key

pki_public_ca_crt:
  file.absent:
    - name: /etc/pki/ca.crt
