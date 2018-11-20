#!/bin/bash

# Get the data
DROP=$(tac /opt/so/log/stenographer/stenographer.log | grep -m1 drop | awk '{print $14}' | awk -F "=" '{print $2}')

echo "stenodrop drop=$DROP"
