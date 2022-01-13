{% from "cron/map.jinja" import cronmap with context %}

crond_service:
  service.running:
    - name: {{ cronmap.service }}
    - enable: True
    - unless: pgrep soup
