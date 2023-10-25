kibana_curl_config_distributed:
  file.managed:
    - name: /opt/so/conf/kibana/curl.config
    - source: salt://kibana/files/curl.config.template
    - template: jinja
    - mode: 600
    - show_changes: False
