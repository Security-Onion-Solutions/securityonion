logstash:
  pipelines:
    master:
      config:
        - 0010_input_hhbeats.conf
        - 9999_output_redis.conf.jinja
