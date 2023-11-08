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

if ! which pytest &> /dev/null || ! which flake8 &> /dev/null ; then
    echo "Missing dependencies. Consider running the following command:"
    echo "  python -m pip install flake8 pytest pytest-cov"
    exit 1
fi

pip install pytest pytest-cov
flake8 "$TARGET_DIR" "--config=${HOME_DIR}/pytest.ini"
python3 -m pytest "--cov-config=${HOME_DIR}/pytest.ini" "--cov=$TARGET_DIR" --doctest-modules --cov-report=term --cov-fail-under=100  "$TARGET_DIR" 