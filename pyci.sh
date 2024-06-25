#!/bin/bash
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <python_script_dir>"
    echo "Runs tests on all *_test.py files in the given directory."
    exit 1
fi

HOME_DIR=$(dirname "$0")
TARGET_DIR=${1:-.}

PATH=$PATH:/usr/local/bin

if [ ! -d .venv ]; then
    python -m venv .venv
fi

source .venv/bin/activate

if ! pip install flake8 pytest pytest-cov pyyaml; then
    echo "Unable to install dependencies."
    exit 1
fi

flake8 "$TARGET_DIR" "--config=${HOME_DIR}/pytest.ini"
python3 -m pytest "--cov-config=${HOME_DIR}/pytest.ini" "--cov=$TARGET_DIR" --doctest-modules --cov-report=term --cov-fail-under=100  "$TARGET_DIR" 
