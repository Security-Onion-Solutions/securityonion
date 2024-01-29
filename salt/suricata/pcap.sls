{% from 'vars/globals.map.jinja' import GLOBALS %}
{% import_yaml 'suricata/defaults.yaml' as SURICATADEFAULTS %}
{% set SURICATAMERGED = salt['pillar.get']('suricata', SURICATADEFAULTS.suricata, merge=True) %}

suripcapdir:
  file.directory:
    - name: /nsm/suripcap
    - user: 940
    - group: 939
    - mode: 755
    - makedirs: True

{{ SURICATAMERGED.config['af-packet'].threads }}

for thread in afp.threads

suripcapthreaddir:
  file.directory:
    - name: /nsm/suripcap/{{thread}}
    - user: 940
    - group: 939
    - mode: 755
    - makedirs: True

endfor