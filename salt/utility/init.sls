# This state is for checking things
{% if grains['role'] == 'so-master' %}

# Make sure Cross Cluster is good. Will need some logic once we have hot/warm
crossclusterson:
  cmd.script:
    shell: /bin/bash
    runas: socore
    source: salt://utility/bin/crossthestreams.sh
    template: jinja
