 {% from 'vars/globals.map.jinja' import GLOBALS %}

{# we only want this state to run it is CentOS #}
{% if GLOBALS.os == 'OEL' %}

trusted_ca:
  file.managed:
    - name: /etc/pki/ca-trust/source/anchors/ca.crt
    - source: salt://ca/files/ca.crt

update_ca_certs:
  cmd.run:
    - name: update-ca-trust
    - onchanges:
      - file: trusted_ca

{% else %}

desktop_trusted-ca_os_fail:
  test.fail_without_changes:
    - comment: 'SO Desktop can only be installed on Oracle Linux'

{% endif %}
