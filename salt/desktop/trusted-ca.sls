 {% from 'vars/globals.map.jinja' import GLOBALS %}

{# we only want this state to run it is CentOS #}
{% if GLOBALS.os == 'OEL' %}

  {% set global_ca_text = [] %}
  {% set global_ca_server = [] %}
  {% set manager = GLOBALS.manager %}
  {% set x509dict = salt['mine.get'](manager | lower~'*', 'x509.get_pem_entries') %}
    {% for host in x509dict %}
      {% if host.split('_')|last in ['manager', 'managersearch', 'standalone', 'import', 'eval'] %}
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

{% else %}

desktop_trusted-ca_os_fail:
  test.fail_without_changes:
    - comment: 'SO Desktop can only be installed on Oracle Linux'

{% endif %}
