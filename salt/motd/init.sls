{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

so_motd:
  file.managed:
    - name: /etc/motd
    - source: salt://motd/files/so_motd.jinja
    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}