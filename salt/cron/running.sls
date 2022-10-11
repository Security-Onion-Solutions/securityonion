{% from "cron/map.jinja" import cronmap %}

crond_service:
  service.running:
    - name: {{ cronmap.service }}
    - enable: True
    - unless: pgrep soup
