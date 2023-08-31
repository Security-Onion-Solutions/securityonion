{# we only want this state to run it is CentOS #}
{% if grains.os == 'OEL' %}

include:
  - desktop.packages

graphical_target:
  file.symlink:
    - name: /etc/systemd/system/default.target
    - target: /lib/systemd/system/graphical.target
    - force: True
    - require:
      - desktop_packages

{# set users to use gnome-classic #}
{%   for username in salt['file.find'](path='/home/',mindepth=1,maxdepth=1,type='d') %}
{%     set username = username.split('/')[2] %}
{%     if username != 'zeek' %}
{%       if not salt['file.file_exists']('/var/lib/AccountsService/users/' ~ username) %}

{{username}}_session:
  file.managed:
    - name: /var/lib/AccountsService/users/{{username}}
    - source: salt://desktop/files/session.jinja
    - template: jinja
    - defaults:
        USERNAME: {{username}}

{%       endif %}
{%     endif %}
{%   endfor %}

desktop_wallpaper:
  file.managed:
    - name: /usr/local/share/backgrounds/so-wallpaper.jpg
    - source: salt://desktop/files/so-wallpaper.jpg
    - makedirs: True

set_wallpaper:
  file.managed:
    - name: /etc/dconf/db/local.d/00-background
    - source: salt://desktop/files/00-background

run_dconf_update:
  cmd.run:
    - name: 'dconf update'
    - onchanges:
      - file: set_wallpaper

{% else %}

desktop_xwindows_os_fail:
  test.fail_without_changes:
    - comment: 'SO Desktop can only be installed on Oracle Linux'

{% endif %}
