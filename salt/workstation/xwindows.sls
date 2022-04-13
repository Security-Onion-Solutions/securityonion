
{# we only want this state to run it is CentOS #}
{% if grains.os == 'CentOS' %}

include:
  - workstation.packages

graphical_target:
  file.symlink:
    - name: /etc/systemd/system/default.target
    - target: /lib/systemd/system/graphical.target
    - force: True
    - require:
      - pkg: X Window System
      - pkg: graphical_extras

{% else %}

workstation_xwindows_os_fail:
  test.fail_without_changes:
    - comment: 'SO Analyst Workstation can only be installed on CentOS'

{% endif %}
