elastic_auth_pillar:
  file.managed:
    - name: /opt/so/saltstack/local/pillar/elasticsearch/auth.sls
    - contents: |
        elasticsearch:
          auth:
            enabled: False
            users:
              so_elastic_user:
                user: so_elastic
                pass: {{ salt['random.get_str'](20) }}
              so_kibana_user:
                user: so_kibana
                pass: {{ salt['random.get_str'](20) }}
              so_logstash_user:
                user: so_logstash
                pass: {{ salt['random.get_str'](20) }}
              so_beats_user:
                user: so_beats
                pass: {{ salt['random.get_str'](20) }}
              so_monitor_user:
                user: so_monitor
                pass: {{ salt['random.get_str'](20) }}
    # since we are generating a random password, and we don't want that to happen everytime
    # a highstate runs, we only manage the file each user isn't present in the file. if the
    # pillar file doesn't exists, then the default vault provided to pillar.get should not
    # be within the file either, so it should then be created
    - unless:
    {% for so_app_user in salt['pillar.get']('elasticsearch:auth:users', {'so_noapp_user': {'user': 'r@NDumu53Rd0NtDOoP'}}) %}
      - grep {{ so_app_user.user }} /opt/so/saltstack/local/pillar/elasticsearch/auth.sls
    {% endfor%}
