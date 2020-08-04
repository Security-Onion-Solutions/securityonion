logstash:
  pipelines:
    manager:
      config:
        - so/0009_input_beats.conf      
        - so/0010_input_hhbeats.conf
        - so/9998_output_minio.conf.jinja
