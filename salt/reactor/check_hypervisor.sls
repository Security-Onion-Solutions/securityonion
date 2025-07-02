{% if data['id'].endswith('_hypervisor') and data['result'] == True %}

{%   if data['act'] == 'accept' %}
check_and_trigger:
  runner.setup_hypervisor.setup_environment:
    - minion_id: {{ data['id'] }}
{%   endif %}

{%   if data['act'] == 'delete' %}
delete_hypervisor:
  runner.state.orchestrate:
    - args:
      - mods: orch.delete_hypervisor
      - pillar:
          minion_id: {{ data['id'] }}
{%   endif %}

{% endif %}

