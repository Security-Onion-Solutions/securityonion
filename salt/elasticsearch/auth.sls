elastic_auth_pillar:
  file.managed:
    - name: /opt/so/saltstack/local/pillar/elasticsearch/auth.sls
    - contents: |
        elasticsearch:
          auth:
            enabled: False
            user: so_elastic
            pass: {{ salt['random.get_str'](20) }}
