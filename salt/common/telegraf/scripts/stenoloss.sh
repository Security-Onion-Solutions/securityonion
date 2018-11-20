#!/bin/bash

# Get the data
DROP=$(tac /var/log/stenographer/stenographer.log | grep -m1 drop | awk '{print $14}' | awk -F "=" '{print $2}')

echo "stenodrop drop=$DROP"
