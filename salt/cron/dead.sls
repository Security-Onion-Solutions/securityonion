{% from "cron/map.jinja" import cronmap %}

crond_service:
  service.dead:
    - name: {{ cronmap.service }}
    - enable: True
