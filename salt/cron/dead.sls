{% from "cron/map.jinja" import cronmap with context %}

crond_service:
  service.dead:
    - name: {{ cronmap.service }}
    - enable: True
