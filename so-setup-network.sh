#!/bin/bash

# Copyright 2014,2015,2016,2017,2018 Security Onion Solutions, LLC

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Global Variable Section
HOSTNAME=$(cat /etc/hostname)
TOTAL_MEM=`grep MemTotal /proc/meminfo | awk '{print $2}' | sed -r 's/.{3}$//'`
NICS=$(ip link | awk -F: '$0 !~ "lo|vir|veth|br|docker|wl|^[^0-9]"{print $2 " \"" "Interface" "\"" " OFF"}')
CPUCORES=$(cat /proc/cpuinfo | grep processor | wc -l)
LISTCORES=$(cat /proc/cpuinfo | grep processor | awk '{print $3 " \"" "core" "\""}')

# End Global Variable Section

# Functions

accept_salt_key_local() {

  # Accept the key locally on the master
  salt-key -ya $HOSTNAME
}

accept_salt_key_remote() {

  # Accept the key remotely so the device can check in
  ssh -i ~/.ssh/so.key socore@$MSRV sudo salt-key -a $HOSTNAME -y

}

add_master_hostfile() {
  # Pop up an input to get the IP address
  local MSRVIP=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter your Master Server IP Address" 10 60 X.X.X.X 3>&1 1>&2 2>&3)

  # Add the master to the host file if it doesn't resolve
  echo "$MSRV   $MSRVIP" >> /etc/hosts
}

add_socore_user_master() {
  if [ $OS == 'centos' ]; then
    local ADDUSER=adduser
  else
    local ADDUSER=useradd
  fi
  # Add user "socore" to the master. This will be for things like accepting keys.
  groupadd --gid 939 socore
  $ADDUSER --uid 939 --gid 939 --home-dir /opt/so socore
  # Prompt the user to set a password for the user
  passwd socore

}

add_socore_user_notmaster() {

  # Add socore user to the non master system. Probably not a bad idea to make system user
  groupadd --gid 939 socore
  $ADDUSER --uid 939 --gid 939 --home-dir /opt/so --no-create-home socore

}

calculate_useable_cores() {

  # Calculate reasonable core usage
  local CORES4BRO=$(( $CPUCORES/2 - 1 ))
  LBPROCSROUND=$(printf "%.0f\n" $CORES4BRO)
  # We don't want it to be 0
  if [ "$LBPROCSROUND" -lt 1 ]; then
    LBPROCS=1
  else
    LBPROCS=$LBPROCSROUND
  fi

}

chown_salt_master() {

  # Chown the salt dirs on the master for socore
  chown -R socore:socore /opt/so

}

configure_minion() {

  # You have to pass the TYPE to this function so it knows if its a master or not
  local TYPE=$1
  echo "Configuring minion type as $TYPE"
  touch /etc/salt/grains
  echo "role: so-$TYPE" > /etc/salt/grains
  if [ $TYPE == 'master' ]; then
    echo "master: $HOSTNAME" > /etc/salt/minion
    echo "id: $HOSTNAME" >> /etc/salt/minion
  else
    echo "master: $MSRV" > /etc/salt/minion
    echo "id: $HOSTNAME" >> /etc/salt/minion
  fi

  service salt-minion restart

}

copy_master_config() {

  # Copy the master config template to the proper directory
  cp files/master /etc/salt/master
  # Restart the service so it picks up the changes -TODO Enable service on CentOS
  service salt-master restart

}

copy_minion_pillar() {

  # Pass the type so it knows where to copy the pillar
  local TYPE=$1

  # Copy over the pillar
  echo "Copying the pillar over"
  scp -i ~/.ssh/so.key $TMP/$HOSTNAME.sls socore@$MSRV:/opt/so/saltstack/pillar/$TYPE/$HOSTNAME.sls

  }

copy_ssh_key() {

  # Generate SSH key
  mkdir -p ~/.ssh
  cat /dev/zero | ssh-keygen -f ~/.ssh/so.key -t rsa -q -N ""
  chown -R $SUDO_USER:$SUDO_USER ~/.ssh
  #Copy the key over to the master
  ssh-copy-id -f -i ~/.ssh/so.key socore@$MSRV

}

create_bond() {

  # Create the bond interface
  echo "Setting up Bond"

  # Do something different based on the OS
  if [ $OS == 'centos' ]; then
    alias bond0 bonding
    mode=0
    # Create Bond files for the selected monitor interface - TODO
    for BNIC in ${BNICS[@]}; do
      echo "blah"
    done

  else

    # Need to add 17.04 support still
    apt-get -y install ifenslave
    echo "bonding" >> /etc/modules
    modprobe bonding

    # Backup and create a new interface file
    cp /etc/network/interfaces /etc/network/interfaces.sosetup

    local LBACK=$(awk '/auto lo/,/^$/' /etc/network/interfaces)
    local MINT=$(awk "/auto $MNIC/,/^$/" /etc/network/interfaces)

    # Let's set up the new interface file
    # Populate lo and the management interface
    echo $LBACK > $TMP/interfaces
    echo $MINT >> $TMP/interfaces
    cp $TMP/interfaces /etc/network/interfaces

    # Create entries for each interface that is part of the bond.
    for BNIC in ${BNICS[@]}; do

      BNIC=$(echo $BNIC |  cut -d\" -f2)
      echo ""
      echo "auto $BNIC" >> /etc/network/interfaces
      echo "iface $BNIC inet manual" >> /etc/network/interfaces
      echo "  up ip link set \$IFACE promisc on arp off up" >> /etc/network/interfaces
      echo "  down ip link set \$IFACE promisc off down" >> /etc/network/interfaces
      echo "  post-up ethtool -G \$IFACE rx 4096; for i in rx tx sg tso ufo gso gro lro; do ethtool -K \$IFACE \$i off; done" >> /etc/network/interfaces
      echo "  post-up echo 1 > /proc/sys/net/ipv6/conf/\$IFACE/disable_ipv6" >> /etc/network/interfaces
      echo "  bond-master bond0" >> /etc/network/interfaces
      echo ""

    done

    BN=("${BNICS[@]//\"/}")

    echo "auto bond0" >> /etc/network/interfaces
    echo "iface bond0 inet manual" >> /etc/network/interfaces
    echo "  bond-mode 0" >> /etc/network/interfaces
    echo "  bond-slaves $BN" >> /etc/network/interfaces
    echo "  up ip link set \$IFACE promisc on arp off up" >> /etc/network/interfaces
    echo "  down ip link set \$IFACE promisc off down" >> /etc/network/interfaces
    echo "  post-up ethtool -G \$IFACE rx 4096; for i in rx tx sg tso ufo gso gro lro; do ethtool -K \$IFACE \$i off; done" >> /etc/network/interfaces
    echo "  post-up echo 1 > /proc/sys/net/ipv6/conf/\$IFACE/disable_ipv6" >> /etc/network/interfaces
  fi

}

detect_os() {

  # Detect Base OS
  echo "Detecting Base OS"
  if [ -f /etc/redhat-release ]; then
    OS=centos
  elif [ -f /etc/os-release ]; then
    OS=ubuntu
  else
    echo "We were unable to determine if you are using a supported OS."
    exit
  fi

}

docker_install() {

  if [ $INSTALLTYPE == 'MASTERONLY' ] || [ $INSTALLTYPE == 'EVALMODE' ]; then
    apt-get update >>~/sosetup.log 2>&1
    apt-get -y install docker-ce >>~/sosetup.log 2>&1
    docker_registry
    echo "Restarting Docker"
    systemctl restart docker
  else
    apt-key add $TMP/gpg/docker.pub
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    apt-get update >>~/sosetup.log 2>&1
    apt-get -y install docker-ce >>~/sosetup.log 2>&1
    docker_registry
    echo "Restarting Docker"
    systemctl restart docker
  fi

}

docker_registry() {

  echo "Setting up Docker Registry"
  mkdir -p /etc/docker
  # Make the host use the master docker registry
  echo "{" > /etc/docker/daemon.json
  echo "  \"registry-mirrors\": [\"https://$MSRV:5000\"]" >> /etc/docker/daemon.json
  echo "}" >> /etc/docker/daemon.json
  echo "Docker Registry Setup - Complete"

}

es_heapsize() {

  # Determine ES Heap Size
  if [ $TOTAL_MEM -lt 8000 ] ; then
      ES_HEAP_SIZE="600m"
  elif [ $TOTAL_MEM -ge 100000 ]; then
      # Set a max of 25GB for heap size
      # https://www.elastic.co/guide/en/elasticsearch/guide/current/heap-sizing.html
      ES_HEAP_SIZE="25000m"
  else
      # Set heap size to 25% of available memory
      ES_HEAP_SIZE=$(($TOTAL_MEM / 4))"m"
  fi

}

filter_nics() {

  # Filter the NICs that we don't want to see in setup
  FNICS=$(ip link | grep -vw $MNIC | awk -F: '$0 !~ "lo|vir|veth|br|docker|wl|^[^0-9]"{print $2 " \"" "Interface" "\"" " OFF"}')

}

get_main_ip() {

  # Get the main IP address the box is using
  MAINIP=$(ip route get 1 | awk '{print $NF;exit}')

}

got_root() {

  # Make sure you are root
  if [ "$(id -u)" -ne 0 ]; then
          echo "This script must be run using sudo!"
          exit 1
  fi

}

install_cleanup() {

  # Clean up after ourselves
  rm -rf ./installtmp

}
install_prep() {

  # Create a tmp space that isn't in /tmp
  mkdir ./installtmp
  TMP=./installtmp

}

install_master() {

  # Install the salt master package
  if [ $OS == 'centos' ]; then
    yum -y install salt-master
  else
    apt-get install -y salt-master
  fi

  copy_master_config

}

ls_heapsize() {

  # Determine LS Heap Size
  if [ $TOTAL_MEM -ge 16000 ] ; then
      LS_HEAP_SIZE="4192m"
  else
      # Set a max of 1GB heap if you have less than 16GB RAM
      LS_HEAP_SIZE="2g"
  fi

}

master_pillar() {

  # Create the master pillar
  touch /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "master:" > /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  esaccessip: 127.0.0.1" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  esheap: $ES_HEAP_SIZE" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  esclustername: {{ grains.host }}" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  if [ $INSTALLTYPE == 'EVALMODE' ]; then
    echo "  freq: 1" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
    echo "  domainstats: 1" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
    echo "  ls_pipeline_workers: $CPUCORES" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
    echo "  ls_pipeline_batch_size: 125" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
    echo "  ls_input_threads: 1" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
    echo "  ls_batch_count: 125" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  else
    echo "  freq: 0" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
    echo "  domainstats: 0" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  fi
  echo "  lsheap: $LS_HEAP_SIZE" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  lsaccessip: 127.0.0.1" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  elastalert: 1" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  ls_pipeline_workers: $CPUCORES" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  nids_rules: $RULESETUP" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  oinkcode: $OINKCODE" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  access_key: $ACCESS_KEY" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  access_secret: $ACCESS_SECRET" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls

  }

master_static() {

  # Create a static file for global values
  touch /opt/so/saltstack/pillar/static.sls

  echo "static:" >> /opt/so/saltstack/pillar/static.sls
  echo "  hnmaster: $HNMASTER" >> /opt/so/saltstack/pillar/static.sls
  echo "  ntpserver: $NTPSERVER" >> /opt/so/saltstack/pillar/static.sls
  echo "  proxy: $PROXY" >> /opt/so/saltstack/pillar/static.sls
  if [ $MASTERUPDATES == 'MASTER' ]; then
    echo "  masterupdate: 1" >> /opt/so/saltstack/pillar/static.sls
  else
    echo "  masterupdate: 0" >> /opt/so/saltstack/pillar/static.sls
  fi
}

minio_generate_keys() {

  local charSet="[:graph:]"

  ACCESS_KEY=$(cat /dev/urandom | tr -cd "$charSet" | tr -d \' | tr -d \" | head -c 20)
  ACCESS_SECRET=$(cat /dev/urandom | tr -cd "$charSet" | tr -d \' | tr -d \" | head -c 40)

}
node_pillar() {

  # Create the node pillar
  touch $TMP/$HOSTNAME.sls
  echo "node:" > $TMP/$HOSTNAME.sls
  echo "  mainip: $MAINIP" >> $TMP/$HOSTNAME.sls
  echo "  esaccessip: 127.0.0.1" >> $TMP/$HOSTNAME.sls
  echo "  esheap: $NODE_ES_HEAP_SIZE" >> $TMP/$HOSTNAME.sls
  echo "  esclustername: {{ grains.host }}" >> $TMP/$HOSTNAME.sls
  echo "  lsheap: $NODE_LS_HEAP_SIZE" >> $TMP/$HOSTNAME.sls
  echo "  lsaccessip: 127.0.0.1" >> $TMP/$HOSTNAME.sls
  echo "  ls_pipeline_workers: $LSPIPELINEWORKERS" >> $TMP/$HOSTNAME.sls
  echo "  ls_pipeline_batch_size: $LSPIPELINEBATCH" >> $TMP/$HOSTNAME.sls
  echo "  ls_input_threads: $LSINPUTTHREADS" >> $TMP/$HOSTNAME.sls
  echo "  ls_batch_count: $LSINPUTBATCHCOUNT" >> $TMP/$HOSTNAME.sls
  echo "  es_shard_count: $SHARDCOUNT" >> $TMP/$HOSTNAME.sls
  echo "  node_type: $NODETYPE" >> $TMP/$HOSTNAME.sls

}

saltify() {

  # Install updates and Salt
  if [ $OS == 'centos' ]; then
    ADDUSER=adduser

    if [ $INSTALLTYPE == 'MASTERONLY' ] || [ $INSTALLTYPE == 'EVALMODE' ]; then
      yum -y install https://repo.saltstack.com/yum/redhat/salt-repo-latest-2.el7.noarch.rpm

    else

      if [ $MASTERUPDATES == 'MASTER' ]; then
        yum -y install wget
        export http_proxy=http://$MSRV:3142; wget -O $TMP/salt-repo-latest-2.el7.noarch.rpm http://repo.saltstack.com/yum/redhat/salt-repo-latest-2.el7.noarch.rpm
        yum -y install $TMP/salt-repo-latest-2.el7.noarch.rpm
      else
        yum -y install https://repo.saltstack.com/yum/redhat/salt-repo-latest-2.el7.noarch.rpm
      fi
    fi

    yum clean expire-cache
    yum -y install salt-minion yum-utils device-mapper-persistent-data lvm2 openssl
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    yum -y update
    yum -y install docker-ce python-docker

    # Nasty hack but required for now
    if [ $INSTALLTYPE == 'MASTERONLY' ] || [ $INSTALLTYPE == 'EVALMODE' ]; then
      yum -y install salt-master python-m2crypto salt-minion m2crypto
    else
      yum -y install salt-minion python-m2m2crypto m2crypto
    fi


  else
    ADDUSER=useradd
    apt-get -y upgrade

    # Add the pre-requisites for installing docker-ce
    apt-get -y install ca-certificates curl software-properties-common apt-transport-https openssl >>~/sosetup.log 2>&1

    # Grab the version from the os-release file
    UVER=$(grep VERSION_ID /etc/os-release | awk -F '[ "]' '{print $2}')

    # Nasty hack but required for now
    if [ $INSTALLTYPE == 'MASTERONLY' ] || [ $INSTALLTYPE == 'EVALMODE' ]; then

      # Install the repo for salt
      wget --inet4-only -O - https://repo.saltstack.com/apt/ubuntu/$UVER/amd64/latest/SALTSTACK-GPG-KEY.pub | apt-key add -
      echo "deb http://repo.saltstack.com/apt/ubuntu/$UVER/amd64/latest xenial main" > /etc/apt/sources.list.d/saltstack.list

      # Lets get the docker repo added
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
      add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

      # Create a place for the keys
      mkdir -p /opt/so/gpg
      wget --inet4-only -O /opt/so/gpg/SALTSTACK-GPG-KEY.pub https://repo.saltstack.com/apt/ubuntu/$UVER/amd64/latest/SALTSTACK-GPG-KEY.pub
      wget --inet4-only -O /opt/so/gpg/docker.pub https://download.docker.com/linux/ubuntu/gpg
      # Initialize the new repos
      apt-get update >>~/sosetup.log 2>&1
      apt-get -y install salt-minion python-m2crypto >>~/sosetup.log 2>&1

    else

      # Copy down the gpg keys and install them from the master
      mkdir $TMP/gpg
      scp socore@$MSRV:/opt/so/gpg/* $TMP/gpg
      apt-key add $TMP/gpg/SALTSTACK-GPG-KEY.pub
      echo "deb http://repo.saltstack.com/apt/ubuntu/$UVER/amd64/latest xenial main" > /etc/apt/sources.list.d/saltstack.list
      # Initialize the new repos
      apt-get update >>~/sosetup.log 2>&1
      apt-get -y install salt-minion python-m2crypto >>~/sosetup.log 2>&1

    fi

  fi

}

salt_checkin() {
  # Master State to Fix Mine Usage
  if [ $INSTALLTYPE == 'MASTERONLY' ]; then
  salt-call state.apply common >>~/sosetup.log 2>&1
  salt-call state.apply ca >>~/sosetup.log 2>&1
  salt-call state.apply ssl >>~/sosetup.log 2>&1
  echo " *** Restarting Salt to fix any SSL errors. ***"
  service salt-master restart
  sleep 5
  service salt-minion restart
  sleep 5
  salt-call state.highstate

  else

  # Run Checkin
  salt-call state.highstate

  fi

}

salt_checkin_message() {

  # Warn the user that this might take a while
  echo "####################################################"
  echo "##                                                ##"
  echo "##        Applying and Installing everything      ##"
  echo "##             (This will take a while)           ##"
  echo "##                                                ##"
  echo "####################################################"

}

salt_firstcheckin() {

  #First Checkin
  salt-call state.highstate >>~/sosetup.log 2>&1

}

salt_master_directories() {

  # Create salt paster directories
  mkdir -p /opt/so/saltstack/salt
  mkdir -p /opt/so/saltstack/pillar

  # Copy over the salt code and templates
  cp -R pillar/* /opt/so/saltstack/pillar/
  chmod +x /opt/so/saltstack/pillar/firewall/addfirewall.sh
  cp -R salt/* /opt/so/saltstack/salt/

}

sensor_pillar() {

  # Create the sensor pillar
  touch $TMP/$HOSTNAME.sls
  echo "sensor:" > $TMP/$HOSTNAME.sls
  echo "  interface: bond0" >> $TMP/$HOSTNAME.sls
  echo "  mainip: $MAINIP" >> $TMP/$HOSTNAME.sls
  if [ $NSMSETUP == 'ADVANCED' ]; then
    echo "  bro_pins:" >> $TMP/$HOSTNAME.sls
    for PIN in $BROPINS; do
      PIN=$(echo $PIN |  cut -d\" -f2)
    echo "    - $PIN" >> $TMP/$HOSTNAME.sls
    done
    SP=("${SURIPINS[@]//\"/}")
    SPINS=${SP// /,}
    SCOUNT=${#SURIPINS[@]}

    echo "  suripins: $SPINS" >> $TMP/$HOSTNAME.sls
    echo "  surithreads: $SCOUNT"
  else
    echo "  bro_lbprocs: $BASICBRO" >> $TMP/$HOSTNAME.sls
    echo "  suriprocs: $BASICSURI" >> $TMP/$HOSTNAME.sls
  fi
  echo "  brobpf:" >> $TMP/$HOSTNAME.sls
  echo "  pcapbpf:" >> $TMP/$HOSTNAME.sls
  echo "  nidsbpf:" >> $TMP/$HOSTNAME.sls
  echo "  master: $MSRV" >> $TMP/$HOSTNAME.sls
  echo "  homenet: $HNSENSOR" >> $TMP/$HOSTNAME.sls
  echo "  access_key: $ACCESS_KEY" >> $TMP/$HOSTNAME.sls
  echo "  access_secret: $ACCESS_SECRET" >>  $TMP/$HOSTNAME.sls

}

set_initial_firewall_policy() {

  get_main_ip
  if [ $INSTALLTYPE == 'MASTERONLY' ]; then
    printf "  - $MAINIP\n" >> /opt/so/saltstack/pillar/firewall/minions.sls

  fi
  if [ $INSTALLTYPE == 'SENSORONLY' ]; then

    ssh -i ~/.ssh/so.key socore@$MSRV sudo /opt/so/saltstack/pillar/firewall/addfirewall.sh minions $MAINIP
    ssh -i ~/.ssh/so.key socore@$MSRV sudo /opt/so/saltstack/pillar/firewall/addfirewall.sh forward_nodes $MAINIP

  fi
  if [ $INSTALLTYPE == 'STORAGENODE' ]; then
    ssh -i ~/.ssh/so.key socore@$MSRV sudo /opt/so/saltstack/pillar/firewall/addfirewall.sh minions $MAINIP
    ssh -i ~/.ssh/so.key socore@$MSRV sudo /opt/so/saltstack/pillar/firewall/addfirewall.sh storage_nodes $MAINIP
  fi

  if [ $INSTALLTYPE == 'PARSINGNODE' ]; then
    echo "blah"
  fi

  if [ $INSTALLTYPE == 'HOTNODE' ]; then
    echo "blah"
  fi

  if [ $INSTALLTYPE == 'WARMNODE' ]; then
    echo "blah"
  fi

}

set_node_type() {

  # Determine the node type based on whiplash choice
  if [ $INSTALLTYPE == 'STORAGENODE' ]; then
    NODETYPE='storage'
  fi
  if [ $INSTALLTYPE == 'PARSINGNODE' ]; then
    NODETYPE='parser'
  fi
  if [ $INSTALLTYPE == 'HOTNODE' ]; then
    NODETYPE='hot'
  fi
  if [ $INSTALLTYPE == 'WARMNODE' ]; then
    NODETYPE='warm'
  fi

}

set_updates() {
  echo "MASTERUPDATES is $MASTERUPDATES"
  if [ $MASTERUPDATES == 'MASTER' ]; then
    if [ $OS == 'centos' ]; then
      echo "proxy=http://$MSRV:3142" >> /etc/yum.conf

    else

    # Set it up so the updates roll through the master
    echo "Acquire::http::Proxy \"http://$MSRV:3142\";" > /etc/apt/apt.conf.d/00Proxy
    echo "Acquire::https::Proxy \"http://$MSRV:3142\";" >> /etc/apt/apt.conf.d/00Proxy

  fi
    fi
}

update_sudoers() {

  # Update Sudoers so that socore can accept keys without a password
  echo "socore ALL=(ALL) NOPASSWD:/usr/bin/salt-key" | sudo tee -a /etc/sudoers
  echo "socore ALL=(ALL) NOPASSWD:/opt/so/saltstack/pillar/firewall/addfirewall.sh" | sudo tee -a /etc/sudoers

}

###########################################
##                                       ##
##         Whiptail Menu Section         ##
##                                       ##
###########################################

whiptail_basic_bro() {

  BASICBRO=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter the number of bro processes:" 10 60 $LBPROCS 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_basic_suri() {

  BASICSURI=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter the number of Suricata Processes:" 10 60 $LBPROCS 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_bro_pins() {

  BROPINS=$(whiptail --noitem --title "Pin Bro CPUS" --checklist "Please Select $LBPROCS cores to pin Bro to:" 20 78 12 ${LISTCORES[@]} 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus


}

whiptail_bond_nics() {

  BNICS=$(whiptail --title "NIC Setup" --checklist "Please add NICs to the Monitor Interface" 20 78 12 ${FNICS[@]} 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_bond_nics_mtu() {

  # Set the MTU on the monitor interface
  MTU=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter the MTU for the monitor NICs" 10 60 1500 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_cancel() {

  whiptail --title "Security Onion Setup" --msgbox "Cancelling Setup. No changes have been made." 8 78
  install_cleanup
  exit

}

whiptail_check_exitstatus() {

  if [ $1 == '1' ]; then
    echo " They hit cancel"
    whiptail_cancel
  fi

}

whiptail_homenet_master() {

  # Ask for the HOME_NET on the master
  HNMASTER=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter your HOME_NET separated by ," 10 60 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12 3>&1 1>&2 2>&3)

}

whiptail_homenet_sensor() {

  # Ask to inherit from master
  whiptail --title "Security Onion Setup" --yesno "Do you want to inherit the HOME_NET from the Master?" 8 78

  local exitstatus=$?
  if [ $exitstatus == 0 ]; then
    HNSENSOR=inherit
  else
    HNSENSOR=$(whiptail --title "Security Onion Setup" --inputbox \
    "Enter your HOME_NET separated by ," 10 60 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12 3>&1 1>&2 2>&3)
  fi


}
whiptail_install_type() {

  # What kind of install are we doing?
  INSTALLTYPE=$(whiptail --title "Security Onion Setup" --radiolist \
  "Choose Install Type:" 20 78 8 \
  "EVALMODE" "Evaluate all the things" ON \
  "SENSORONLY" "Create a forward only sensor" OFF \
  "MASTERONLY" "Start a new grid" OFF \
  "STORAGENODE" "Add a Storage Hot Node with parsing" OFF \
  "PARSINGNODE" "Add a dedicated Parsing Node" OFF \
  "HOTNODE" "Add a Hot Node (Storage Node without Parsing)" OFF \
  "WARMNODE" "Add a Warm Node to an existing Hot or Storage node" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_management_nic() {

  MNIC=$(whiptail --title "NIC Setup" --radiolist "Please select your management NIC" 20 78 12 ${NICS[@]} 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_nids() {

  NIDS=$(whiptail --title "Security Onion Setup" --radiolist \
  "Choose which IDS to run:" 20 78 4 \
  "Suricata" "Suricata 4.X" ON 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_oinkcode() {

  OINKCODE=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter your oinkcode" 10 60 XXXXXXX 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_make_changes() {

  whiptail --title "Security Onion Setup" --yesno "We are going to set this machine up as a $INSTALLTYPE. Please hit YES to make changes or NO to cancel." 8 78

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_management_server() {

  MSRV=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter your Master Server HOSTNAME" 10 60 XXXX 3>&1 1>&2 2>&3)

  # See if it resolves. Otherwise prompt to add to host file
  TESTHOST=$(host $MSRV)

  if [[ $TESTHOST = *"not found"* ]]; then
    add_master_hostfile
  fi


  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_network_notice() {

  whiptail --title "Security Onion Setup" --yesno "Since this is a network install we assume the management interface, DNS, Hostname, etc are already set up. Hit YES to continue." 8 78

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_advanced() {

  NODESETUP=$(whiptail --title "Security Onion Setup" --radiolist \
  "What type of config would you like to use?:" 20 78 4 \
  "NODEBASIC" "Install Storage Node with recommended settings" ON \
  "NODEADVANCED" "Advanced Node Setup" OFF 3>&1 1>&2 2>&3 )

}

whiptail_node_es_heap() {

  es_heapsize
  NODE_ES_HEAP_SIZE=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter ES Heap Size: \n \n(Recommended value is pre-populated)" 10 60 $ES_HEAP_SIZE 3>&1 1>&2 2>&3)

}

whiptail_node_ls_heap() {

  ls_heapsize
  NODE_LS_HEAP_SIZE=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter LogStash Heap Size: \n \n(Recommended value is pre-populated)" 10 60 $LS_HEAP_SIZE 3>&1 1>&2 2>&3)

}

whiptail_node_ls_pipeline_worker() {

  LSPIPELINEWORKERS=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter LogStash Pipeline Workers: \n \n(Recommended value is pre-populated)" 10 60 $CPUCORES 3>&1 1>&2 2>&3)

}

whiptail_node_ls_pipline_batchsize() {

  LSPIPELINEBATCH=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter LogStash Pipeline Batch Size: \n \n(Default value is pre-populated)" 10 60 125 3>&1 1>&2 2>&3)

}

whiptail_node_ls_input_threads() {

  LSINPUTTHREADS=$(whiptail --title "Security Onion Setup" --inputbox \
    "\nEnter LogStash Input Threads: \n \n(Default value is pre-populated)" 10 60 1 3>&1 1>&2 2>&3)

}

whiptail_node_ls_input_batch_count() {

  LSINPUTBATCHCOUNT=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter LogStash Input Batch Count: \n \n(Default value is pre-populated)" 10 60 125 3>&1 1>&2 2>&3)

}

whiptail_rule_setup() {

  # Get pulled pork info
  RULESETUP=$(whiptail --title "Security Onion Setup" --radiolist \
  "What IDS rules to use?:" 20 140 4 \
  "ETOPEN" "Emerging Threats Open - no oinkcode required" ON \
  "ETPRO" "Emerging Threats PRO - requires ETPRO oinkcode" OFF \
  "TALOSET" "Snort Subscriber (Talos) ruleset and Emerging Threats NoGPL ruleset - requires Snort Subscriber oinkcode" OFF \
  "TALOS" "Snort Subscriber (Talos) ruleset only and set a Snort Subscriber policy - requires Snort Subscriber oinkcode" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_sensor_config() {

  NSMSETUP=$(whiptail --title "Security Onion Setup" --radiolist \
  "What type of configuration would you like to use?:" 20 78 4 \
  "BASIC" "Install NSM components with recommended settings" ON \
  "ADVANCED" "Configure each component individually" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_setup_complete() {

  whiptail --title "Security Onion Setup" --msgbox "Finished installing this as an $INSTALLTYPE. A reboot is recommended." 8 78
  install_cleanup
  exit

}

whiptail_shard_count() {

  SHARDCOUNT=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter ES Shard Count: \n \n(Default value is pre-populated)" 10 60 125 3>&1 1>&2 2>&3)

}

whiptail_suricata_pins() {

  FILTEREDCORES=$(echo ${LISTCORES[@]} ${BROPINS[@]} | tr -d '"' | tr ' ' '\n' | sort | uniq -u | awk '{print $1 " \"" "core" "\""}')
  SURIPINS=$(whiptail --noitem --title "Pin Suricata CPUS" --checklist "Please Select $LBPROCS cores to pin Suricata to:" 20 78 12 ${FILTEREDCORES[@]} 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_master_updates() {

  MASTERUPDATES=$(whiptail --title "Security Onion Setup" --radiolist \
  "How would you like to download updates for your grid?:" 20 78 4 \
  "MASTER" "Have the master node act as a proxy for OS/Docker updates." ON \
  "OPEN" "Have each node connect to the Internet for updates" OFF 3>&1 1>&2 2>&3 )

}

whiptail_node_updates() {

  NODEUPDATES=$(whiptail --title "Security Onion Setup" --radiolist \
  "How would you like to download updates for this node?:" 20 78 4 \
  "MASTER" "Download OS/Docker updates from the Master." ON \
  "OPEN" "Download updates directly from the Internet" OFF 3>&1 1>&2 2>&3 )

}

whiptail_you_sure() {

  whiptail --title "Security Onion Setup" --yesno "Are you sure you want to install Security Onion over the internet?" 8 78

}
########################
##                    ##
##   End Functions    ##
##                    ##
########################

#####################
##                 ##
##    Let's Go!    ##
##                 ##
#####################

# Check for prerequisites
got_root
detect_os

if [ $OS == ubuntu ]; then
  # Override the horrible Ubuntu whiptail color pallete
  update-alternatives --set newt-palette /etc/newt/palette.original
fi

# Question Time

if (whiptail_you_sure); then

  # Create a dir to get started
  install_prep

  # Let folks know they need their management interface already set up.
  whiptail_network_notice

  # Go ahead and gen the keys so we can use them for any sensor type
  #minio_generate_keys
  # What kind of install are we doing?
  whiptail_install_type

  if [ $INSTALLTYPE == 'MASTERONLY' ]; then

    # Pick the Management NIC
    whiptail_management_nic
    # Select Snort or Suricata
    whiptail_nids
    # Snag the HOME_NET
    whiptail_homenet_master
    # Pick your Ruleset
    whiptail_rule_setup

    # Get the code if it isn't ET Open
    if [ $RULESETUP != 'ETOPEN' ]; then
      # Get the code
      whiptail_oinkcode
    fi

    # Find out how to handle updates
    whiptail_master_updates

    # Last Chance to back out
    whiptail_make_changes

    # Add the user so we can sit back and relax
    echo ""
    echo "**** Please set a password for socore. You will use this password when setting up other Nodes/Sensors"
    echo ""
    add_socore_user_master

    # Install salt and dependencies
    echo " ** Installing Salt and Dependencies **"
    saltify >>~/sosetup.log 2>&1
    docker_install
    # Configure the Minion
    echo " ** Configuring Minion **"
    configure_minion master >>~/sosetup.log 2>&1
    echo " ** Installing Salt Master **"
    install_master >>~/sosetup.log 2>&1
    # Copy the data over
    salt_master_directories >>~/sosetup.log 2>&1

    update_sudoers
    chown_salt_master
    es_heapsize
    ls_heapsize
    # Set the static values
    master_static
    echo "** Generating the master pillar **"
    master_pillar
    # Do a checkin to push the key up
    echo "** Pushing the key up to Master **"
    salt_firstcheckin >>~/sosetup.log 2>&1
    # Accept the Master Key
    echo "** Accepting the key on the master **"
    accept_salt_key_local
    echo "** Setting the initial firewall policy **"
    set_initial_firewall_policy
    # Do the big checkin but first let them know it will take a bit.
    salt_checkin_message
    salt_checkin

    whiptail_setup_complete

  fi

  if [ $INSTALLTYPE == 'SENSORONLY' ]; then
    whiptail_management_nic
    filter_nics
    whiptail_bond_nics
    whiptail_management_server
    whiptail_master_updates
    set_updates
    whiptail_nids
    whiptail_sensor_config
    # Calculate lbprocs so we can call it in the prompts
    calculate_useable_cores
    if [ $NSMSETUP == 'ADVANCED' ]; then
      whiptail_bro_pins
      whiptail_suricata_pins
      whiptail_bond_nics_mtu
    else
      whiptail_basic_bro
      whiptail_basic_suri
    fi
    whiptail_make_changes
    copy_ssh_key
    set_initial_firewall_policy
    sensor_pillar
    create_bond
    saltify
    docker_install
    configure_minion SENSOR
    copy_minion_pillar sensors
    salt_firstcheckin
    # Accept the Salt Key
    accept_salt_key_remote
    # Do the big checkin but first let them know it will take a bit.
    salt_checkin_message
    salt_checkin

    whiptail_setup_complete

  fi

  if [ $INSTALLTYPE == 'EVALMODE' ]; then
    whiptail_management_nic
    filter_nics
    whiptail_bond_nics
    whiptail_management_server
    whiptail_nids
    whiptail_sensor_config
    whiptail_make_changes
    configure_minion
    copy_ssh_key
    create_bond
    saltify
    docker_install
    configure_minion sensor
    copy_minion_pillar sensors
    salt_firstcheckin
    accept_salt_key_local
    salt_checkin_message
    salt_checkin
  fi

  if [ $INSTALLTYPE == 'STORAGENODE' ] || [ $INSTALLTYPE == 'PARSINGNODE' ] || [ $INSTALLTYPE == 'HOTNODE' ] || [ $INSTALLTYPE == 'WARMNODE' ]; then
    whiptail_management_nic
    whiptail_management_server
    whiptail_master_updates
    set_updates
    es_heapsize
    ls_heapsize
    whiptail_node_advanced
    if [ $NODESETUP == 'NODEADVANCED' ]; then
      whiptail_node_es_heap
      whiptail_node_ls_heap
      whiptail_node_ls_pipeline_worker
      whiptail_node_ls_pipline_batchsize
      whiptail_node_ls_input_threads
      whiptail_node_ls_input_batch_count
    else
      NODE_ES_HEAP_SIZE=$ES_HEAP_SIZE
      NODE_LS_HEAP_SIZE=$LS_HEAP_SIZE
      LSPIPELINEWORKERS=1
      LSPIPELINEBATCH=125
      LSINPUTTHREADS=1
      LSINPUTBATCHCOUNT=125
    fi
    whiptail_make_changes
    copy_ssh_key
    set_initial_firewall_policy
    saltify
    docker_install
    configure_minion node
    set_node_type
    node_pillar
    copy_minion_pillar nodes
    salt_checkin
    # Accept the Salt Key
    accept_salt_key_remote
    # Do the big checkin but first let them know it will take a bit.
    salt_checkin_message
    salt_checkin

    whiptail_setup_complete
  fi

else
    exit
fi
