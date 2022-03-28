   
    {% set global_ca_text = [] %}
    {% set global_ca_server = [] %}
    {% set manager = salt['grains.get']('master') %}
    {% set x509dict = salt['mine.get'](manager | lower~'*', 'x509.get_pem_entries') %}
    {% for host in x509dict %}
      {% if host.split('_')|last in ['manager', 'managersearch', 'standalone', 'import'] %}
        {% do global_ca_text.append(x509dict[host].get('/etc/pki/ca.crt')|replace('\n', '')) %}
        {% do global_ca_server.append(host) %}
      {% endif %}
    {% endfor %}
    {% set trusttheca_text = global_ca_text[0] %}
    {% set ca_server = global_ca_server[0] %}

trusted_ca:
  x509.pem_managed:
    - name: /etc/pki/ca-trust/source/anchors/ca.crt
    - text:  {{ trusttheca_text }}

update_ca_certs:
  cmd.run:
    - name: update-ca-trust
    - onchanges:
      - x509: trusted_ca
