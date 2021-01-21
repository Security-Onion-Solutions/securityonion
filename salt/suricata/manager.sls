{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

surilocaldir:
  file.directory:
    - name: /opt/so/saltstack/local/salt/suricata
    - user: socore
    - group: socore
    - makedirs: True

ruleslink:
  file.symlink:
    - name: /opt/so/saltstack/local/salt/suricata/rules
    - user: socore
    - group: socore
    - target: /opt/so/rules/nids

refresh_salt_master_fileserver_suricata_ruleslink:
  salt.runner:
    - name: fileserver.update
    - onchanges:
      - file: ruleslink

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}