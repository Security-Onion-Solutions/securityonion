#!/bin/bash
/usr/bin/docker exec so-bro /opt/bro/bin/broctl netstats | awk '{print $(NF-2),$(NF-1),$NF}' | awk -F '[ =]' '{RCVD += $2;DRP += $4;TTL += $6} END { print "rcvd: " RCVD, "dropped: " DRP, "total: " TTL}'
