#!/bin/bash
/usr/bin/docker exec so-zeek env -i PATH=/bin:/usr/bin:/sbin:/usr/sbin:/opt/bin:/usr/local/bin:/usr/local/sbin "runuser -l zeek -c '/opt/zeek/bin/zeekctl netstats'" | awk '{print $(NF-2),$(NF-1),$NF}' | awk -F '[ =]' '{RCVD += $2;DRP += $4;TTL += $6} END { print "rcvd: " RCVD, "dropped: " DRP, "total: " TTL}' >> /nsm/zeek/logs/packetloss.log 2>&1
