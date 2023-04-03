{% from 'vars/globals.map.jinja' import GLOBALS %}

{# we only want this state to run it is CentOS #}
{% if GLOBALS.os == 'Rocky' %}

remove_graphical_target:
  file.symlink:
    - name: /etc/systemd/system/default.target
    - target: /lib/systemd/system/multi-user.target
    - force: True

{% else %}
workstation_trusted-ca_os_fail:
  test.fail_without_changes:
    - comment: 'SO Analyst Workstation can only be installed on CentOS'

{% endif %}
