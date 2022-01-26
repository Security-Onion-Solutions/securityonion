{% if grains.role in ['so-helix', 'so-eval', 'so-manager', 'so-standalone', 'so-managersearch', 'so-import' ] %}

pki_private_key:
  file.absent:
    - name: /etc/pki/ca.key

pki_public_ca_crt:
  file.absent:
    - name: /etc/pki/ca.crt

{% else %}

not_a_ca:
  test.succeed_without_changes:
    - name: no_ca
    - comment: "Not a CA, so no CA to remove."

{% endif %}

remove_ca-certificates.crt:
  file.absent:
    - name: /etc/ssl/certs/ca-certificates.crt
