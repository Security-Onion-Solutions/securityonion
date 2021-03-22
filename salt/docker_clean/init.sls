{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

prune_images:
  cmd.run:
    - name: so-docker-prune

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
