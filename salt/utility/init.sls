{% from 'allowed_states.map.jinja' import allowed_states %}

{% if sls in allowed_states %}
  {% set ELASTICUSER = salt['pillar.get']('elasticsearch:auth:user', '' ) %}
  {% set ELASTICPASS = salt['pillar.get']('elasticsearch:auth:pass', '' ) %}

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
    - defaults:
        ELASTICCURL: "curl"
    {% if salt['pillar.get']('elasticsearch:auth_enabled', False) %}
    - context:
        ELASTICCURL: "curl --user {{ELASTICUSER}}:{{ELASTICPASS}}"
    {% endif %}

  {% endif %}
  {% if grains['role'] in ['so-eval', 'so-import'] %}
fixsearch:
  cmd.script:
    - shell: /bin/bash
    - cwd: /opt/so
    - runas: socore
    - source: salt://utility/bin/eval
    - template: jinja
    - defaults:
        ELASTICCURL: "curl"
    {% if salt['pillar.get']('elasticsearch:auth_enabled', False) %}
    - context:
        ELASTICCURL: "curl --user {{ELASTICUSER}}:{{ELASTICPASS}}"
    {% endif %}
  {% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
