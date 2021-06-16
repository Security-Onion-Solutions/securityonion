{% set so_elastic_user_pass = salt['random.get_str'](20) %}
{% set so_kibana_user_pass = salt['random.get_str'](20) %}
{% set so_logstash_user_pass = salt['random.get_str'](20) %}
{% set so_beats_user_pass = salt['random.get_str'](20) %}
{% set so_monitor_user_pass = salt['random.get_str'](20) %}

elastic_auth_pillar:
  file.managed:
    - name: /opt/so/saltstack/local/pillar/elasticsearch/auth.sls
    - mode: 600
    - reload_pillar: True
    - contents: |
        elasticsearch:
          auth:
            enabled: False
            users:
              so_elastic_user:
                user: so_elastic
                pass: {{ so_elastic_user_pass }}
              so_kibana_user:
                user: so_kibana
                pass: {{ so_kibana_user_pass }}
              so_logstash_user:
                user: so_logstash
                pass: {{ so_logstash_user_pass }}
              so_beats_user:
                user: so_beats
                pass: {{ so_beats_user_pass }}
              so_monitor_user:
                user: so_monitor
                pass: {{ so_monitor_user_pass }}
    # since we are generating a random password, and we don't want that to happen everytime
    # a highstate runs, we only manage the file each user isn't present in the file. if the
    # pillar file doesn't exists, then the default vault provided to pillar.get should not
    # be within the file either, so it should then be created
    - unless:
    {% for so_app_user, values in salt['pillar.get']('elasticsearch:auth:users', {'so_noapp_user': {'user': 'r@NDumu53Rd0NtDOoP'}}).items() %}
      - grep {{ values.user }} /opt/so/saltstack/local/pillar/elasticsearch/auth.sls
    {% endfor%}
