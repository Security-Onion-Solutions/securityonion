#!/bin/bash

COMMAND=$1
SENSORONI_CONTAINER=${SENSORONI_CONTAINER:-so-sensoroni}

function ci() {
    HOME_DIR=$(dirname "$0")
    TARGET_DIR=${1:-.}

    PATH=$PATH:/usr/local/bin

    if ! which pytest &> /dev/null || ! which flake8 &> /dev/null ; then
        echo "Missing dependencies. Consider running the following command:"
        echo "  python -m pip install flake8 pytest pytest-cov"
        exit 1
    fi

    flake8 "$TARGET_DIR" "--config=${HOME_DIR}/pytest.ini"
    pytest "$TARGET_DIR" "--cov-config=${HOME_DIR}/pytest.ini" "--cov=$TARGET_DIR" --doctest-modules --cov-report=term --cov-fail-under=100
}

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
  ci
fi
