{% set NEWNODE = salt['pillar.get']('setup:newnode') %}

{% if NEWNODE.split('_')|last in ['searchnode', 'heavynode'] %}
{{NEWNODE}}_download_logstash_elasticsearch:
  salt.state:
    - tgt: {{ NEWNODE }}
    - sls:
      - repo.client
      - docker
      - logstash.download
      - elasticsearch.download
{% endif %}
