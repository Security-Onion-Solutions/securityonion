{%- set PIPELINE = salt['pillar.get']('global:pipeline', 'minio') %}
logstash:
  pipelines:
    manager:
      config:
        - so/0009_input_beats.conf      
        - so/0010_input_hhbeats.conf
        {%- if PIPELINE == "minio"%}
        - so/9998_output_minio.conf.jinja
        {%- else %}
        - so/9999_output_redis.conf.jinja
        {%- endif %}