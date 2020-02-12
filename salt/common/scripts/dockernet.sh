#!/bin/bash

if [ ! -f /opt/so/state/dockernet.state ]; then
    docker network create -d bridge so-elastic-net
    touch /opt/so/state/dockernet.state
else
    exit
fi
