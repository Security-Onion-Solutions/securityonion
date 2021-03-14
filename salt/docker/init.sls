{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

installdocker:
  pkg.installed:
    - name: docker-ce

# Make sure Docker is running!
docker:
  service.running:
    - enable: True

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}