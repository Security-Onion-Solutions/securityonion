logstash:
  pipelines:
    fleet:
      config:
        - so/0012_input_elastic_agent.conf     
        - so/9806_output_lumberjack_fleet.conf.jinja