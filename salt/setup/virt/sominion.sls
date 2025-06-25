# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'setup/virt/soinstall.map.jinja' import DATA %}

create_pillar:
  event.send:
    - name: setup/so-minion
    - data:
        HYPERVISOR_HOST: {{ grains.hypervisor_host }}
        MAINIP: {{ DATA.MAINIP }}
        MNIC: {{ DATA.MNIC }}
        NODE_DESCRIPTION: '{{ DATA.NODE_DESCRIPTION }}'
        NODETYPE: {{ DATA.NODETYPE }}
        CPUCORES: {{ DATA.CPUCORES }}
        {% if 'CORECOUNT' in DATA %}
        CORECOUNT: {{ DATA.CORECOUNT }}
        {% endif %}
        {% if 'INTERFACE' in DATA %}
        INTERFACE: {{ DATA.INTERFACE }}
        {% endif %}
        {% if 'ES_HEAP_SIZE' in DATA %}
        ES_HEAP_SIZE: {{ DATA.ES_HEAP_SIZE }}
        {% endif %}
        {% if 'LSHOSTNAME' in DATA %}
        LSHOSTNAME: {{ DATA.LSHOSTNAME }}
        {% endif %}
        {% if 'LSHEAP' in DATA %}
        LS_HEAP_SIZE: {{ DATA.LSHEAP }}
        {% endif %}
