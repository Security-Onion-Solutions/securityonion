{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

yumconf:
  file.managed:
    - name: /etc/yum.conf
    - source: salt://yum/etc/yum.conf.jinja
    - mode: 644
    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}