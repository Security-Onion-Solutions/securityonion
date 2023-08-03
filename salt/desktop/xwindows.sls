{% from 'vars/globals.map.jinja' import GLOBALS %}

{# we only want this state to run it is CentOS #}
{% if GLOBALS.os == 'OEL' %}

include:
  - desktop.packages

graphical_target:
  file.symlink:
    - name: /etc/systemd/system/default.target
    - target: /lib/systemd/system/graphical.target
    - force: True
    - require:
      - desktop_packages

convert_gnome_classic:
  cmd.script:
    - name: salt://desktop/scripts/convert-gnome-classic.sh

{% else %}

desktop_xwindows_os_fail:
  test.fail_without_changes:
    - comment: 'SO Desktop can only be installed on Oracle Linux'

{% endif %}
