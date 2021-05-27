elastic_auth_pillar:
  file.managed:
    - name: /opt/so/saltstack/local/pillar/elasticsearch/auth.sls
    - contents: |
        elasticsearch:
          auth:
            enabled: False
            user: so_elastic
            pass: {{ salt['random.get_str'](20) }}
    # since we are generating a random password, and we don't want that to happen everytime
    # a highstate runs, we only manage the file if it doesn't exist
    - unless: ls /opt/so/saltstack/local/pillar/elasticsearch/auth.sls
