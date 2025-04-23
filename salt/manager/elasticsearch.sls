elastic_curl_config_distributed:
  file.managed:
    - name: /opt/so/saltstack/local/salt/elasticsearch/curl.config
    - source: salt://elasticsearch/files/curl.config.template
    - template: jinja
    - mode: 640
    - show_changes: False
