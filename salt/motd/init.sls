package_update_reboot_required_motd:
  file.managed:
    - name: /etc/motd
    - source: salt://motd/files/package_update_reboot_required.jinja
    - template: jinja
