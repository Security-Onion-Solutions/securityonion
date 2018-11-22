#!/bin/bash

# Get the data
OLDPCAP=$(find /nsm/pcap -type f -printf '%Cs %p\n' | sort | head -n 1 | awk {'print $1'})
DATE=$(date +%s)
AGE=$(($DATE - $OLDPCAP))

echo "pcapage seconds=$AGE"
