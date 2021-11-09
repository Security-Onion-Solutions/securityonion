{% set kibana_encryptedSavedObjects_encryptionKey = salt['pillar.get']('kibana:secrets:encryptedSavedObjects:encryptionKey', salt['random.get_str'](72)) %}

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
