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
        ES_HEAP_SIZE: {{ DATA.ES_HEAP_SIZE }}
        PATCHSCHEDULENAME: {{ DATA.PATCHSCHEDULENAME }}
        INTERFACE: {{ DATA.INTERFACE }}
        NODETYPE: {{ DATA.NODETYPE }}
        CORECOUNT: {{ DATA.CORECOUNT }}
        LSHOSTNAME: {{ DATA.LSHOSTNAME }}
        LSHEAP: {{ DATA.LSHEAP }}
        CPUCORES: {{ DATA.CPUCORES }}
        IDH_MGTRESTRICT: {{ DATA.IDH_MGTRESTRICT }}
        IDH_SERVICES: {{ DATA.IDH_SERVICES }}
        CPU: {{ DATA.CPU }}
        MEMORY: {{ DATA.MEMORY }}
        DISKS: {{ DATA.DISKS }}
        COPPER: {{ DATA.COPPER }}
        SFP: {{ DATA.SFP }}
