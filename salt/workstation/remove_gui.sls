{# we only want this state to run it is CentOS #}
{% if grains.os == 'CentOS' %}

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
