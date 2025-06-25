{% if data['act'] == 'accept' and data['id'].endswith(('_hypervisor', '_managerhyper')) and data['result'] == True %}
check_and_trigger:
  runner.setup_hypervisor.setup_environment:
    - minion_id: {{ data['id'] }}
{% endif %}
