{% from 'vars/globals.map.jinja' import GLOBALS %}

{# we only want this state to run it is CentOS #}
{% if GLOBALS.os == 'Rocky' %}

include:
  - desktop.packages

graphical_target:
  file.symlink:
    - name: /etc/systemd/system/default.target
    - target: /lib/systemd/system/graphical.target
    - force: True
    - require:
      - pkg: cinnamon

{% else %}

workstation_xwindows_os_fail:
  test.fail_without_changes:
    - comment: 'SO Analyst Workstation can only be installed on Rocky'

{% endif %}
