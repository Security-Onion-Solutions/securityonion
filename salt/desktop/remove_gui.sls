{# we only want this state to run it is CentOS #}
{% if grains.os == 'OEL' %}

remove_graphical_target:
  file.symlink:
    - name: /etc/systemd/system/default.target
    - target: /lib/systemd/system/multi-user.target
    - force: True

{% else %}
desktop_trusted-ca_os_fail:
  test.fail_without_changes:
    - comment: 'SO Desktop can only be installed on Oracle Linux'

{% endif %}
