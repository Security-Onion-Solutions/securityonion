so_motd:
  file.managed:
    - name: /etc/motd
    - source: salt://motd/files/so_motd.jinja
    - template: jinja
