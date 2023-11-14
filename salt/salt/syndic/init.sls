{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'salt/map.jinja' import SALTVERSION %}

install_salt_syndic:
  pkg.installed:
    - name: salt-syndic
    - version: {{ SALTVERSION }}
    - update_holds: True

salt_syndic_service:
  service.running:
     - name: salt-syndic
     - enable: True
