#!/bin/bash

UNPARSED=$(redis-cli llen logstash:unparsed | awk '{print $1}')
PARSED=$(redis-cli llen logstash:parsed | awk '{print $1}')

echo "redisqueue unparsed=$UNPARSED,parsed=$PARSED"
