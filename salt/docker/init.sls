{% set show_top = salt['state.show_top']() %}
{% set top_states = show_top.values() | join(', ') %}

{% if 'docker' in top_states %}

installdocker:
  pkg.installed:
    - name: docker-ce

# Make sure Docker is running!
docker:
  service.running:
    - enable: True

{% else %}

docker_state_not_allowed:
  test.fail_without_changes:
    - name: docker_state_not_allowed

{% endif %}