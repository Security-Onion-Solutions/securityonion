logstash:
  pipelines:
    search:
      config:
        - so/0900_input_redis.conf.jinja
        - so/9000_output_zeek.conf.jinja
        - so/9002_output_import.conf.jinja
        - so/9034_output_syslog.conf.jinja
        - so/9100_output_osquery.conf.jinja
        - so/9400_output_suricata.conf.jinja
        - so/9500_output_beats.conf.jinja
        - so/9600_output_ossec.conf.jinja
        - so/9700_output_strelka.conf.jinja
  templates:
    - so/so-beats-template.json.jinja
    - so/so-common-template.json
    - so/so-firewall-template.json.jinja
    - so/so-flow-template.json.jinja
    - so/so-ids-template.json.jinja
    - so/so-import-template.json.jinja
    - so/so-osquery-template.json.jinja
    - so/so-ossec-template.json.jinja
    - so/so-strelka-template.json.jinja
    - so/so-syslog-template.json.jinja
    - so/so-zeek-template.json.jinja
