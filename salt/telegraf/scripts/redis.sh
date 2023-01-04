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

    UNPARSED=$(redis-cli llen logstash:unparsed | awk '{print $1}')
    PARSED=$(redis-cli llen logstash:parsed | awk '{print $1}')

    echo "redisqueue unparsed=$UNPARSED,parsed=$PARSED"

fi

exit 0
