{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set OLDVERSIONS = ['2.0.0-rc.1','2.0.1-rc.1','2.0.2-rc.1','2.0.3-rc.1','2.1.0-rc.2','2.2.0-rc.3','2.3.0','2.3.1','2.3.2']%}

{% for VERSION in OLDVERSIONS %}
remove_images_{{ VERSION }}:
  docker_image.absent:
    - force: True
    - images:
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-acng:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-thehive-cortex:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-curator:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-domainstats:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-elastalert:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-elasticsearch:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-filebeat:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-fleet:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-fleet-launcher:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-freqserver:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-grafana:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-idstools:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-influxdb:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-kibana:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-kratos:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-logstash:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-minio:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-mysql:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-nginx:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-pcaptools:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-playbook:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-redis:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-soc:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-soctopus:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-steno:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-strelka-frontend:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-strelka-manager:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-strelka-backend:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-strelka-filestream:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-suricata:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-telegraf:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-thehive:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-thehive-es:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-wazuh:{{ VERSION }}'
      - '{{ MANAGER }}:5000/{{ IMAGEREPO }}/so-zeek:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-acng:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-thehive-cortex:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-curator:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-domainstats:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-elastalert:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-elasticsearch:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-filebeat:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-fleet:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-fleet-launcher:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-freqserver:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-grafana:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-idstools:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-influxdb:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-kibana:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-kratos:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-logstash:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-minio:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-mysql:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-nginx:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-pcaptools:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-playbook:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-redis:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-soc:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-soctopus:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-steno:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-strelka-frontend:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-strelka-manager:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-strelka-backend:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-strelka-filestream:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-suricata:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-telegraf:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-thehive:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-thehive-es:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-wazuh:{{ VERSION }}'
      - '{{ MANAGER }}:5000/securityonion/so-zeek:{{ VERSION }}'
{% endfor %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}