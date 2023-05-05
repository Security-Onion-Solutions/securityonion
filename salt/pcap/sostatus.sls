append_so-steno_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-steno
    - unless: grep -q so-steno /opt/so/conf/so-status/so-status.conf
