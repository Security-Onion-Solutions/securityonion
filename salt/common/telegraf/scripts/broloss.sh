#!/bin/bash

BROLOG=$(tac /nsm/bro/logs/packetloss.log | head -2)
declare RESULT=($BROLOG)
CURRENTDROP=${RESULT[3]}
PASTDROP=${RESULT[9]}
DROPPED=$(($CURRENTDROP - $PASTDROP))
CURRENTPACKETS=${RESULT[5]}
PASTPACKETS=${RESULT[11]}
TOTAL=$(($CURRENTPACKETS - $PASTPACKETS))
LOSS=$(echo $DROPPED $TOTAL / p | dc)
echo "brodrop drop=$LOSS"
