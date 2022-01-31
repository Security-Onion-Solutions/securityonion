{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

  {% set DIGITS = "1234567890" %}
  {% set LOWERCASE = "qwertyuiopasdfghjklzxcvbnm" %}
  {% set UPPERCASE = "QWERTYUIOPASDFGHJKLZXCVBNM" %}
  {% set SYMBOLS = "~!@#$^&*()-_=+[]|;:,.<>?" %}
  {% set CHARS = DIGITS~LOWERCASE~UPPERCASE~SYMBOLS %}
  {% set so_elastic_user_pass = salt['pillar.get']('elasticsearch:auth:users:so_elastic_user:pass', salt['random.get_str'](72, chars=CHARS)) %}
  {% set so_kibana_user_pass = salt['pillar.get']('elasticsearch:auth:users:so_kibana_user:pass', salt['random.get_str'](72, chars=CHARS)) %}
  {% set so_logstash_user_pass = salt['pillar.get']('elasticsearch:auth:users:so_logstash_user:pass', salt['random.get_str'](72, chars=CHARS)) %}
  {% set so_beats_user_pass = salt['pillar.get']('elasticsearch:auth:users:so_beats_user:pass', salt['random.get_str'](72, chars=CHARS)) %}
  {% set so_monitor_user_pass = salt['pillar.get']('elasticsearch:auth:users:so_monitor_user:pass', salt['random.get_str'](72, chars=CHARS)) %}
  {% set auth_enabled = salt['pillar.get']('elasticsearch:auth:enabled', False) %}

elastic_auth_pillar:
  file.managed:
    - name: /opt/so/saltstack/local/pillar/elasticsearch/auth.sls
    - mode: 600
    - reload_pillar: True
    - contents: |
        elasticsearch:
          auth:
            enabled: {{ auth_enabled }}
            users:
              so_elastic_user:
                user: so_elastic
                pass: "{{ so_elastic_user_pass }}"
              so_kibana_user:
                user: so_kibana
                pass: "{{ so_kibana_user_pass }}"
              so_logstash_user:
                user: so_logstash
                pass: "{{ so_logstash_user_pass }}"
              so_beats_user:
                user: so_beats
                pass: "{{ so_beats_user_pass }}"
              so_monitor_user:
                user: so_monitor
                pass: "{{ so_monitor_user_pass }}"
    - show_changes: False
{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
