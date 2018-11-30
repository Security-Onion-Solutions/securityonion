#!/bin/bash
/usr/bin/docker exec -it so-bro /opt/bro/bin/broctl netstats | awk -F '[ =]' '{RCVD += $5;DRP += $7;TTL += $9} END { print "rcvd: " RCVD, "dropped: " DRP, "total: " TTL}' >> /nsm/bro/logs/packetloss.log
