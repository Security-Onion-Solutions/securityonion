yumconf:
  file.managed:
    - name: /etc/yum.conf
    - source: salt://yum/etc/yum.conf.jinja
    - mode: 644
    - template: jinja