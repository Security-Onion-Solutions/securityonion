{% set show_top = salt['state.show_top']() %}
{% set top_states = show_top.values() | join(', ') %}

{% if 'utility' in top_states %}

# This state is for checking things
{% if grains['role'] in ['so-manager', 'so-managersearch', 'so-standalone'] %}
# Make sure Cross Cluster is good. Will need some logic once we have hot/warm
crossclusterson:
  cmd.script:
    - shell: /bin/bash
    - cwd: /opt/so
    - runas: socore
    - source: salt://utility/bin/crossthestreams
    - template: jinja

{% endif %}
{% if grains['role'] in ['so-eval', 'so-import'] %}
fixsearch:
  cmd.script:
    - shell: /bin/bash
    - cwd: /opt/so
    - runas: socore
    - source: salt://utility/bin/eval
    - template: jinja
{% endif %}

{% else %}

utility_state_not_allowed:
  test.fail_without_changes:
    - name: utility_state_not_allowed

{% endif %}
