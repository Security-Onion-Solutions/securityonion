logstash:
  pipelines:
    manager:
      config:
        - so/0011_input_endgame.conf
        - so/0012_input_elastic_agent.conf
        - so/0013_input_lumberjack_fleet.conf
        - so/9999_output_redis.conf.jinja