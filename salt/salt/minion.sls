{% from 'salt/map.jinja' import COMMON with context %}
{% from 'salt/map.jinja' import UPGRADECOMMAND with context %}
{% from 'salt/map.jinja' import SALTVERSION %}
{% from 'salt/map.jinja' import INSTALLEDSALTVERSION %}

include:
  - salt

install_salt_minion:
  cmd.run:
    - name: |
        exec 0>&- # close stdin
        exec 1>&- # close stdout
        exec 2>&- # close stderr
        nohup /bin/sh -c '{{ UPGRADECOMMAND }}' &
    - onlyif: "[[ '{{INSTALLEDSALTVERSION}}' != '{{SALTVERSION}}' ]]"

salt_minion_package:
  pkg.installed:
    - pkgs:
      - {{ COMMON }}
      - salt-minion
    - hold: True

salt_minion_service:
  service.running:
    - name: salt-minion
    - enable: True