logstash:
  pipelines:
    eval:
      config:
        - so/0800_input_eval.conf
        - so/1002_preprocess_json.conf
        - so/1033_preprocess_snort.conf
        - so/7100_osquery_wel.conf
        - so/8999_postprocess_rename_type.conf
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
    - so/so-ossec-template.json
    - so/so-strelka-template.json
    - so/so-template.json
    - so/so-zeek-template.json
