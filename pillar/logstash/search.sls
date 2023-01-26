logstash:
  pipelines:
    search:
      config:
        - so/0900_input_redis.conf.jinja
        - so/9805_output_elastic_agent.conf.jinja
        - so/9900_output_endgame.conf.jinja
