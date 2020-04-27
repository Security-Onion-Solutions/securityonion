#!/bin/bash

INFLUXSIZE=$(du -s -B1 /host/nsm/influxdb | awk {'print $1'})

echo "influxsize bytes=$INFLUXSIZE"
