{% if data['id'].endswith(('_hypervisor', '_managerhyper')) %}
check_and_trigger:
  runner.setup_hypervisor.setup_environment: []
{% endif %}
