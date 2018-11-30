#!/bin/bash

# Get the data
OLDPCAP=$(find /host/nsm/pcap -type f -exec stat -c'%n %Z' {} + | sort | grep -v "\." | head -n 1 | awk {'print $2'})
DATE=$(date +%s)
AGE=$(($DATE - $OLDPCAP))

echo "pcapage seconds=$AGE"
