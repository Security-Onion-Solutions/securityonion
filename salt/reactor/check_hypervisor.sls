{% if data['id'].endswith(('_hypervisor', '_managerhyper')) %}
check_and_trigger:
  runner.state.orchestrate:
    - args:
        - mods: orch.setup_hypervisor
{% endif %}
