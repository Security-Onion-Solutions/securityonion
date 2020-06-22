{% from 'suricata/suricata_config.map.jinja' import suricata_defaults as suricata with context %}

test_suri_config:
  file.managed:
    - name: /tmp/test.yaml
    - source: salt://suricata/files/test.jinja
    - context:
        suricata: {{ suricata | json }}
    - template: jinja