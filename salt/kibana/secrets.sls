{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

  {% set DIGITS = "1234567890" %}
  {% set LOWERCASE = "qwertyuiopasdfghjklzxcvbnm" %}
  {% set UPPERCASE = "QWERTYUIOPASDFGHJKLZXCVBNM" %}
  {% set SYMBOLS = "~!@#$^&*()-_=+[]|;:,.<>?" %}
  {% set CHARS = DIGITS~LOWERCASE~UPPERCASE~SYMBOLS %}
  {% set kibana_encryptedSavedObjects_encryptionKey = salt['pillar.get']('kibana:secrets:encryptedSavedObjects:encryptionKey', salt['random.get_str'](72, chars=CHARS)) %}
  {% set kibana_security_encryptionKey = salt['pillar.get']('kibana:secrets:security:encryptionKey', salt['random.get_str'](72, chars=CHARS)) %}
  {% set kibana_reporting_encryptionKey = salt['pillar.get']('kibana:secrets:reporting:encryptionKey', salt['random.get_str'](72, chars=CHARS)) %}

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
              encryptionKey: "{{ kibana_encryptedSavedObjects_encryptionKey }}"
            security:
              encryptionKey: "{{ kibana_security_encryptionKey }}"
            reporting:
              encryptionKey: "{{ kibana_reporting_encryptionKey }}"
    - show_changes: False

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
