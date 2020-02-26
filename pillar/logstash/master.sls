logstash:
  pipelines:
    master:
      config:
        - so/0010_input_hhbeats.conf
        - so/9999_output_redis.conf.jinja
