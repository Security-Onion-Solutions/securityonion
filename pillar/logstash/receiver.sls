logstash:
  pipelines:
    receiver:
      config:
        - so/0011_input_endgame.conf
        - so/0012_input_elastic_agent.conf
        - so/9999_output_redis.conf.jinja
        
