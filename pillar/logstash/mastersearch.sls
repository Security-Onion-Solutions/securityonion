logstash:
  pipelines:
    master:
      config: "/usr/share/logstash/pipelines/master/*.conf"
    search:
      config: "/usr/share/logstash/pipelines/search/*.conf"
