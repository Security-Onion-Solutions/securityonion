{% from 'allowed_states.map.jinja' import allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}

{% if sls in allowed_states %}
  {% if grains['role'] in ['so-eval', 'so-import'] %}
fixsearch:
  cmd.script:
    - shell: /bin/bash
    - cwd: /opt/so
    - source: salt://utility/bin/eval
    - template: jinja
    - defaults:
        GLOBALS: {{ GLOBALS }}
  {% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
