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
    - so/so-beats-template.json
    - so/so-common-template.json
    - so/so-firewall-template.json
    - so/so-ids-template.json
    - so/so-import-template.json
    - so/so-osquery-template.json
    - so/so-ossec-template.json
    - so/so-strelka-template.json
    - so/so-syslog-template.json
    - so/so-zeek-template.json
