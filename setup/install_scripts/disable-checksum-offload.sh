#!/bin/bash

if [ "$NM_DISPATCHER_ACTION" == "pre-up" ]; then
    if ["$DEVICE_IFACE" !== "$MAININT"]; then
        for i in rx tx sg tso ufo gso gro lro; do 
            ethtool -K $DEVICE_IFACE $i off; 
        done
    fi
fi
