#!/bin/bash

INFLUXSIZE=$(du -s -k /host/nsm/influxdb | awk {'print $1'})

echo "influxsize kbytes=$INFLUXSIZE"
