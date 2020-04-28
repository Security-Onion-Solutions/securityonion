#!/usr/bin/env bash

# This script adds sensors/nodes/etc to the nodes tab

TYPE=$1
NAME=$2
IPADDRESS=$3
CPUS=$4
GUID=$5
MANINT=$6
ROOTFS=$7
NSM=$8
MONINT=$9
#NODETYPE=$10
#HOTNAME=$11

echo "Seeing if this host is already in here. If so delete it"
if grep -q $NAME "/opt/so/saltstack/pillar/data/$TYPE.sls"; then
  echo "Node Already Present - Let's re-add it"
  awk -v blah="  $NAME:" 'BEGIN{ print_flag=1 }
{
    if( $0 ~ blah )
    {
       print_flag=0;
       next
    }
    if( $0 ~ /^  [a-zA-Z0-9]+:$/ )
    {
        print_flag=1;
    }
    if ( print_flag == 1 )
        print $0

} ' /opt/so/saltstack/pillar/data/$TYPE.sls > /opt/so/saltstack/pillar/data/tmp.$TYPE.sls
mv /opt/so/saltstack/pillar/data/tmp.$TYPE.sls /opt/so/saltstack/pillar/data/$TYPE.sls
echo "Deleted $NAME from the tab. Now adding it in again with updated info"
fi
echo "  $NAME:" >> /opt/so/saltstack/pillar/data/$TYPE.sls
echo "    ip: $IPADDRESS" >> /opt/so/saltstack/pillar/data/$TYPE.sls
echo "    manint: $MANINT" >> /opt/so/saltstack/pillar/data/$TYPE.sls
echo "    totalcpus: $CPUS" >> /opt/so/saltstack/pillar/data/$TYPE.sls
echo "    guid: $GUID" >> /opt/so/saltstack/pillar/data/$TYPE.sls
echo "    rootfs: $ROOTFS" >> /opt/so/saltstack/pillar/data/$TYPE.sls
echo "    nsmfs: $NSM" >> /opt/so/saltstack/pillar/data/$TYPE.sls
if [ $TYPE == 'sensorstab' ]; then
  echo "    monint: $MONINT" >> /opt/so/saltstack/pillar/data/$TYPE.sls
  salt-call state.apply common queue=True
fi
if [ $TYPE == 'evaltab' ]; then
  echo "    monint: $MONINT" >> /opt/so/saltstack/pillar/data/$TYPE.sls
  salt-call state.apply common queue=True
  salt-call state.apply utility queue=True
fi
#if [ $TYPE == 'nodestab' ]; then
#  echo "    nodetype: $NODETYPE" >> /opt/so/saltstack/pillar/data/$TYPE.sls
#  echo "    hotname: $HOTNAME" >> /opt/so/saltstack/pillar/data/$TYPE.sls
#fi
