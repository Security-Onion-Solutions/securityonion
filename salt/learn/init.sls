{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set module_list = salt['pillar.get']('learn:modules', [] ) %}

{% if module_list|length != 0 %}}
include:
{% for module in module_list %}
  - .{{ module }}
{% endfor %}
{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
