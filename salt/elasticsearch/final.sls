include:
  - elasticsearch.enabled

{% if GLOBALS.role in GLOBALS.manager_roles %}
so-es-cluster-settings:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-cluster-settings
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: elasticsearch_sbin_jinja
{% endif %}

so-elasticsearch-ilm-policy-load:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-ilm-policy-load
    - cwd: /opt/so
    - require:
      - docker_container: so-elasticsearch
      - file: so-elasticsearch-ilm-policy-load-script
    - onchanges:
      - file: so-elasticsearch-ilm-policy-load-script

so-elasticsearch-templates-reload:
  file.absent:
    - name: /opt/so/state/estemplates.txt

so-elasticsearch-templates:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-templates-load
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: elasticsearch_sbin_jinja

so-elasticsearch-pipelines:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-pipelines {{ GLOBALS.hostname }}
    - require:
      - docker_container: so-elasticsearch
      - file: so-elasticsearch-pipelines-script

so-elasticsearch-roles-load:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-roles-load
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: elasticsearch_sbin_jinja
