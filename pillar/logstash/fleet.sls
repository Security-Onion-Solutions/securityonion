logstash:
  pipelines:
    fleet:
      config:
        - so/0012_input_elastic_agent.conf     
        - so/9805_output_elastic_agent.conf.jinja