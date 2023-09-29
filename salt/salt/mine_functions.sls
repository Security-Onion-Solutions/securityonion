mine_functions:
  file.managed:
    - name: /etc/salt/minion.d/mine_functions.conf
    - source: salt://salt/etc/minion.d/mine_functions.conf.jinja
    - template: jinja
