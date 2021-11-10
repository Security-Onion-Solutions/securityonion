{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

  {% set kibana_encryptedSavedObjects_encryptionKey = salt['pillar.get']('kibana:secrets:encryptedSavedObjects:encryptionKey', salt['random.get_str'](72)) %}

kibana_pillar_directory:
  file.directory:
    - name: /opt/so/saltstack/local/pillar/kibana

kibana_secrets_pillar:
  file.managed:
    - name: /opt/so/saltstack/local/pillar/kibana/secrets.sls
    - mode: 600
    - reload_pillar: True
    - contents: |
        kibana:
          secrets:
            encryptedSavedObjects:
              encryptionKey: {{ kibana_encryptedSavedObjects_encryptionKey }}
    - show_changes: False

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
