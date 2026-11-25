#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
{%- set REDIS_PASS = salt['pillar.get']('redis:config:requirepass', '0') %}
export REDISCLI_AUTH={{ REDIS_PASS }}
# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    UNPARSED=$(valkey-cli llen logstash:unparsed | awk '{print $1}')
    PARSED=$(valkey-cli llen logstash:parsed | awk '{print $1}')
    MEM_USED=$(valkey-cli info memory | grep used_memory_peak_perc | cut -d ":" -f2 | sed "s/%//")
    
    echo "redisqueue unparsed=$UNPARSED,parsed=$PARSED,mem_used=$MEM_USED"

fi

exit 0
