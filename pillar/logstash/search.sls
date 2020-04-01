logstash:
  pipelines:
    search:
      config:
	- so/0900_input_redis.conf.jinja
        - so/9000_output_bro.conf.jinja
        - so/9002_output_import.conf.jinja
        - so/9033_output_snort.conf.jinja
        - so/9100_output_osquery.conf.jinja
        - so/9400_output_suricata.conf.jinja
        - so/9500_output_beats.conf.jinja
        - so/9600_output_ossec.conf.jinja
        - so/9700_output_strelka.conf.jinja
  templates:
    - so/so-beats-template.json
    - so/so-common-template.json
    - so/so-zeek-template.json
