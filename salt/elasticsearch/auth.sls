{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

  {% set so_elastic_user_pass = salt['pillar.get']('elasticsearch:auth:users:so_elastic_user:pass', salt['random.get_str'](72)) %}
  {% set so_kibana_user_pass = salt['pillar.get']('elasticsearch:auth:users:so_kibana_user:pass', salt['random.get_str'](72)) %}
  {% set so_logstash_user_pass = salt['pillar.get']('elasticsearch:auth:users:so_logstash_user:pass', salt['random.get_str'](72)) %}
  {% set so_beats_user_pass = salt['pillar.get']('elasticsearch:auth:users:so_beats_user:pass', salt['random.get_str'](72)) %}
  {% set so_monitor_user_pass = salt['pillar.get']('elasticsearch:auth:users:so_monitor_user:pass', salt['random.get_str'](72)) %}

elastic_auth_pillar:
  file.managed:
    - name: /opt/so/saltstack/local/pillar/elasticsearch/auth.sls
    - mode: 600
    - reload_pillar: True
    - contents: |
        elasticsearch:
          auth:
            enabled: True
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

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
