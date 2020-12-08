#!/usr/bin/env bash

# This script adds sensors/nodes/etc to the nodes tab
default_salt_dir=/opt/so/saltstack/default
local_salt_dir=/opt/so/saltstack/local
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
if grep -q $NAME "$local_salt_dir/pillar/data/$TYPE.sls"; then
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

} ' $local_salt_dir/pillar/data/$TYPE.sls > $local_salt_dir/pillar/data/tmp.$TYPE.sls
mv $local_salt_dir/pillar/data/tmp.$TYPE.sls $local_salt_dir/pillar/data/$TYPE.sls
echo "Deleted $NAME from the tab. Now adding it in again with updated info"
fi
echo "  $NAME:" >> $local_salt_dir/pillar/data/$TYPE.sls
echo "    ip: $IPADDRESS" >> $local_salt_dir/pillar/data/$TYPE.sls
echo "    manint: $MANINT" >> $local_salt_dir/pillar/data/$TYPE.sls
echo "    totalcpus: $CPUS" >> $local_salt_dir/pillar/data/$TYPE.sls
echo "    guid: $GUID" >> $local_salt_dir/pillar/data/$TYPE.sls
echo "    rootfs: $ROOTFS" >> $local_salt_dir/pillar/data/$TYPE.sls
echo "    nsmfs: $NSM" >> $local_salt_dir/pillar/data/$TYPE.sls
if [ $TYPE == 'sensorstab' ]; then
  echo "    monint: bond0" >> $local_salt_dir/pillar/data/$TYPE.sls
  salt-call state.apply grafana queue=True
fi
if [ $TYPE == 'evaltab' ] || [ $TYPE == 'standalonetab' ]; then
  echo "    monint: bond0" >> $local_salt_dir/pillar/data/$TYPE.sls
  if [ ! $10 ]; then
    salt-call state.apply grafana queue=True
    salt-call state.apply utility queue=True
  fi
fi
if [ $TYPE == 'nodestab' ]; then
  salt-call state.apply elasticseach queue=True
#  echo "    nodetype: $NODETYPE" >> $local_salt_dir/pillar/data/$TYPE.sls
#  echo "    hotname: $HOTNAME" >> $local_salt_dir/pillar/data/$TYPE.sls
fi
