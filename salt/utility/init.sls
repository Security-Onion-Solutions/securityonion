# This state is for checking things
{% if grains['role'] == 'so-master' %}
{% if salt['pillar.get']('nodestab','') %}
# Make sure Cross Cluster is good. Will need some logic once we have hot/warm
crossclusterson:
  cmd.script:
    - shell: /bin/bash
    - cwd: /root
    - runas: socore
    - source: salt://utility/bin/crossthestreams.sh
    - template: jinja

{% endif %}
{% endif %}
{% if grains['role'] == 'so-eval' %}
fixsearch:
  cmd.script:
    - shell: /bin/bash
    - cwd: /root
    - runas: socore
    - source: salt://utility/bin/eval.sh
    - template: jinja
{% endif %}
