#!/bin/bash

COMMAND=$1
SENSORONI_CONTAINER=${SENSORONI_CONTAINER:-so-sensoroni}

function download() {
    ANALYZERS=$1
    if [[ $ANALYZERS = "all" ]]; then
        ANALYZERS="*/"
    fi
    for ANALYZER in $ANALYZERS; do
        rm -fr $ANALYZER/site-packages
        mkdir -p $ANALYZER/source-packages
        rm -fr $ANALYZER/source-packages/*
        docker exec -it $SENSORONI_CONTAINER pip download -r /opt/sensoroni/analyzers/$ANALYZER/requirements.txt -d /opt/sensoroni/analyzers/$ANALYZER/source-packages
    done
}

if [[ "$COMMAND" == "download" ]]; then
  download "$2"
else
  ../../../../pyci.sh $@
fi
