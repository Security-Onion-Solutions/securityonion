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

# End Global Variable Section

# Functions

bro_calculate_lbprocs() {
  #Calculate total lbprocs for basic install
}
configure_minion() {
  local TYPE=$1

  touch /etc/salt/grains
  echo "role: so-$TYPE" > /etc/salt/grains
  echo "master: $MASTER" > /etc/salt/minion
  service salt-minion start
}
copy_pillar() {
  local TYPE=$1

  if [ $TYPE = 'STORAGENODE' ]; then
    PLOC="nodes"
  else
    PLOC="sensors"
  fi

  # Make the minion check in so the key gets there
  salt-call state.highstate

  # Copy over the pillar
  scp /tmp/$HOSTNAME.sls /opt/so/saltstack/pillar/$PLOC/

  # Accept the key
  ssh socore@$MASTERSRV 'sudo salt-key -ya $HOSTNAME'
}
configure_sensor() {

  # Create the pillar file for the sensor
  touch /tmp/$HOSTNAME.sls
  echo "sensors:" > /tmp/$HOSTNAME.sls
  echo "  interface: bond0" >> /tmp/$HOSTNAME.sls
  echo "  bro_lbprocs: $LBPROCS" >> /tmp/$HOSTNAME.sls
  # Need to add pins loop

}

copy_ssh_key() {
  # Generate and copy SSH key
  cat /dev/zero | ssh-keygen -t rsa -q -N ""
  #Copy the key over to the master
  ssh-copy-id socore@$MASTER
}

create_bond() {
  # Create the bond interface
  echo "Setting up Bond"
  if [ $OS == 'centos' ]; then
    alias bond0 bonding
    mode=0
    # Create Bond files

  else
    echo bonding >> /etc/modules
    modprobe bonding
  fi
}

create_socore_password() {
  # Enter a password for socore
}

detect_os() {
  # Detect Base OS
  if [ -f /etc/redhat-release ]; then
    OS=centos
  elif [ -f /etc/os-release ]; then
    OS=ubuntu
  else
    echo "We were unable to determine if you are using a supported OS."
    exit
  fi
}

disk_space() {
  # Give me Disk Space
}

es_heapsize() {
  # Determine ES Heap Size
  if [ $TOTAL_MEM -lt 8000 ] ; then
      ES_HEAP_SIZE="600m"
  elif [ $TOTAL_MEM -ge 124000 ]; then
      # Set a max of 31GB for heap size
      # https://www.elastic.co/guide/en/elasticsearch/guide/current/heap-sizing.html
      ES_HEAP_SIZE="31000m"
  else
      # Set heap size to 25% of available memory
      ES_HEAP_SIZE=$(($TOTAL_MEM / 4))"m"
  fi
}

filter_nics() {
  FNICS=$(ip link | grep -vw $MNIC | awk -F: '$0 !~ "lo|vir|veth|br|docker|wl|^[^0-9]"{print $2 " \"" "Interface" "\"" " OFF"}')
}

got_root() {
  if [ "$(id -u)" -ne 0 ]; then
          echo "This script must be run using sudo!"
          exit 1
  fi
}

install_master() {
  yum -y install salt-master
}

ls_heapsize() {
  # Determine LS Heap Size
  if [ $TOTAL_MEM -ge 16000 ] ; then
      LS_HEAP_SIZE="4192m"
  else
      # Set a max of 1GB heap if you have less than 16GB RAM
      LS_HEAP_SIZE="1g"
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

  salt-call state.highstate
  salt-key -qya $HOSTNAME
  salt-call state.highstate

node_pillar() {
  # Create the node pillar
  touch /tmp/$HOSTNAME.sls
  echo "node:" > /tmp/$HOSTNAME.sls
  echo "  esaccessip: 127.0.0.1" >> /tmp/$HOSTNAME.sls
  echo "  esheap: $ES_HEAP_SIZE" >> /tmp/$HOSTNAME.sls
  echo "  esclustername: {{ grains.host }}" >> /tmp/$HOSTNAME.sls
  echo "  lsheap: $LS_HEAP_SIZE" >> /tmp/$HOSTNAME.sls
  echo "  lsaccessip: 127.0.0.1" >> /tmp/$HOSTNAME.sls
  echo "  ls_pipeline_workers: $CPUCORES" >> /tmp/$HOSTNAME.sls
  echo "  ls_pipeline_batch_size: 125" >> /tmp/$HOSTNAME.sls
  echo "  ls_input_threads: 1" >> /tmp/$HOSTNAME.sls
  echo "  ls_batch_count: 125" >> /tmp/$HOSTNAME.sls
}


}

saltify() {
  # Install updates and Salt
  if [ $OS == 'centos' ]; then
    ADDUSER=adduser
    yum -y install https://repo.saltstack.com/yum/redhat/salt-repo-latest-2.el7.noarch.rpm
    yum clean expire-cache
    yum -y install salt-minion yum-utils device-mapper-persistent-data lvm2
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  else
    ADDUSER=useradd
    apt-get -y upgrade

    # Add the pre-requisites for installing docker-ce
    apt-get -y install ca-certificates curl software-properties-common apt-transport-https

    # grab the version from the os-release file
    UVER=$(grep VERSION_ID /etc/os-release | awk -F '[ "]' '{print $2}')

    # Install the repo for salt
    wget -O - https://repo.saltstack.com/apt/ubuntu/$UVER/amd64/latest/SALTSTACK-GPG-KEY.pub | apt-key add -
    echo "deb http://repo.saltstack.com/apt/ubuntu/$UVER/amd64/latest xenial main" > /etc/apt/sources.list.d/saltstack.list

    # Lets get the docker repo added
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

    # Initialize the new repos
    apt-get update
    apt-get -y install salt-minion
  fi
}

salt_master_directories() {
  # Create salt directories
  mkdir -p /opt/so/saltstack/salt
  mkdir -p /opt/so/saltstack/pillar
  cp -Rv pillar/* /opt/so/saltstack/pillar/
  cp -Rv salt/* /opt/so/saltstack/salt/
}

update_sudoers() {

  # Update Sudoers
  echo "socore ALL=(ALL) NOPASSWD:/usr/bin/salt-key" | sudo tee -a /etc/sudoers

}

whiptail_bro_pins() {

}
whiptail_bond_nics() {

  BNICS=$(whiptail --title "NIC Setup" --checklist "Please add NICs to the Monitor Interface" 20 78 12 ${FNICS[@]} 3>&1 1>&2 2>&3 )

}

whiptail_install_type() {

  # What kind of install are we doing?
  INSTALLTYPE=$(whiptail --title "Security Onion Setup" --radiolist \
  "Choose Install Type:" 20 78 4 \
  "EVALMODE" "Evaluate all the things" ON \
  "SENSORONLY" "Create a forward only sensor" OFF \
  "MASTERONLY" "Start a new grid" OFF \
  "STORAGENODE" "Add a Storage Node" OFF 3>&1 1>&2 2>&3 )

}

whiptail_management_nic() {

  MNIC=$(whiptail --title "NIC Setup" --radiolist "Please select your management NIC" 20 78 12 ${NICS[@]} 3>&1 1>&2 2>&3 )

}

whiptail_nids() {

  NIDS=$(whiptail --title "Security Onion Setup" --radiolist \
  "Choose which IDS to run:" 20 78 4 \
  "Suricata" "Evaluate all the things" ON 3>&1 1>&2 2>&3 )

}

whiptail_oinkcode() {

  OINKCODE=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter your oinkcode" 10 60 XXXXXXX 3>&1 1>&2 2>&3)

}

whiptail_management_server() {

  MASTERSRV=$(whiptail --title "Enter your Master Server IP Address" --inputbox 10 60 1.2.3.4 3>&1 1>&2 2>&3)

}

whiptail_network_notice() {

  whiptail --title "Security Onion Setup" --msgbox "Since this is a network install we assume the management interface, DNS, Hostname, etc are already set up. You must hit OK to continue." 8 78

}

whiptail_rule_setup() {

  # Get pulled pork info
  RULESETUP=$(whiptail --title "Security Onion Setup" --radiolist \
  "What IDS rules to use?:" 20 78 4 \
  "ETOPEN" "Emerging Threats Open - no oinkcode required" ON \
  "ETPRO" "Emerging Threats PRO - requires ETPRO oinkcode" OFF \
  "TALOSET" "Snort Subscriber (Talos) ruleset and Emerging Threats NoGPL ruleset - requires Snort Subscriber oinkcode" OFF \
  "TALOS" "Snort Subscriber (Talos) ruleset only and set a Snort Subscriber policy - requires Snort Subscriber oinkcode" OFF 3>&1 1>&2 2>&3 )

}

whiptail_sensor_config() {

  NSMSETUP=$(whiptail --title "Security Onion Setup" --radiolist \
  "What type of config would you like to use?:" 20 78 4 \
  "BASIC" "Install NSM components with recommended settings" ON \
  "ADVANCED" "Configure each component individually" OFF 3>&1 1>&2 2>&3 )

}

whiptail_you_sure() {

  whiptail --title "Security Onion Setup" --yesno "Are you sure you want to install Security Onion over the internet?" 8 78

}
# End Functions

# Check for prerequisites
got_root
detect_os

# Question Time

if (whiptail_you_sure) then

	# Let folks know they need their management interface already set up.
	whiptail_network_notice

  # What kind of install are we doing?
  whiptail_install_type

  # Configure NICs for boxes that will be running a sensor
  if [ $INSTALLTYPE != 'MASTERONLY' ] || [ $INSTALLTYPE != 'STORAGENODE' ]; then

    # Pick which interface you want to use as the Management
    whiptail_management_nic
    # Filter out the management NIC from the monitor NICs
    filter_nics
    # Choose what NICS to include in the bond
    whiptail_bond_nics

  fi

  if [ $INSTALLTYPE == 'SENSORONLY' ] || [ $INSTALLTYPE == 'STORAGENODE' ]; then

    # Get the master server for the install
    whiptail_management_server

  fi

  # Time to get asnwers to questions so we can fill out the pillar file
  if [ $INSTALLTYPE != 'MASTERONLY' ] || [ $INSTALLTYPE != 'STORAGENODE' ]; then

    # Pick you NIDS. Currently on Suricata
    whiptail_nids
    # Basic or Advanced setup?
    whiptail_sensor_config

    if [ $NSMSETUP == 'BASIC' ]; then

      bro_calculate_lbprocs

    fi

    if [ $NSMSETUP == 'ADVANCED' ]; then
      # Display CPU list for pinning
      whiptail_bro_pins
      # Pin steno
      # Pin Suricata
    fi
    # Ask how many CPUs to use for bro
  fi

  if [ $INSTALLTYPE != 'SENSORONLY' ] || [ $INSTALLTYPE != 'STORAGENODE' ]; then
    whiptail_rule_setup

    # Get the code if it isn't ET Open
    if [ $RULESETUP != 'ETOPEN' ]; then
      # Get the code
      whiptail_oinkcode
    fi


  fi

  #########################
  ## Do all the things!! ##
  #########################

  # Need to ask if you are sure before proceeding

  if [ $INSTALLTYPE == 'MASTERONLY']; then

  fi
  if [ $INSTALLTYPE == 'SENSORONLY' ]; then
    # Make this a sensor

    # Copy over the ssh key
    copy_ssh_key
    # Create the bond interface
    create_bond
    # Install Salt
    saltify


  fi
  if [ $INSTALLTYPE == 'STORAGENODE' ]; then
    # Make this a storage node
    # Copy over the ssh key
    copy_ssh_key
    # Install Salt
    saltify
  fi
  if [ $INSTALLTYPE == 'EVALMODE']; then
    create_bond
  fi




  if [ $INSTALLTYPE != 'SENSORONLY' ] || [ $INSTALLTYPE != 'STORAGENODE' ]; then
      install_master
  fi

  # Create so-core user
  mkdir -p /opt/so/conf

  # Create the salt directories if this isn't a stadnalone sensor
  if [ $INSTALLTYPE != 'SENSORONLY' ] || [ $INSTALLTYPE != 'STORAGENODE' ]; then
    salt_directories
  fi

  # Add socore user to the system
  groupadd --gid 939 socore
  $ADDUSER --uid 939 --gid 939 --home-dir /opt/so --no-create-home socore

  chown -R 939:939 /opt/so

  # Add the grain on the sensor

  # Create the salt goodness
  if [ $INSTALLTYPE == 'SENSORONLY' ]; then

    # Create the grains file for the sensor

    # SCP the pillar file to the master
    scp /tmp/$HOSTNAME.sls socore@$MASTERSRV:/opt/so/saltstack/pillar/sensors/

    # Accept the key on the master
    ssh socore@$MASTERSRV 'sudo salt-key -ya $HOSTNAME'
    # Grab the ssl key for lumberjack from the master
    scp socore@$MASTERSRV:/some/path /some/path


  fi

  # Do that same thing on all the others but drop em into the right place
  if [ $INSTALLTYPE != 'SENSORONLY' ] || [ $INSTALLTYPE != 'STORAGENODE' ]; then

    # Create the grains file for the Master
    touch /etc/salt/grains
    echo "role: so-master" > /etc/salt/grains

    # Set up the minion to talk to itself
    echo "master: $HOSTNAME" > /etc/salt/minion

    # Copy the master config over
    cp files/master /etc/salt/master
    # Comment this out for now
    # chown -R socore:socore /etc/salt

    # Start salt master and minion
    service salt-master restart
    service salt-minion restart

    # Sudoers

    # Create the Master Pillar
    es_heapsize
    ls_heapsize
    master_pillar

    # Determine Disk space
    # Calculate half of available disk space for ELSA log_size_limit
    #DISK_SIZE_K=`df /nsm |grep -v "^Filesystem" | awk '{print $2}'`
    #let DISK_SIZE=DISK_SIZE_K*1000
    #let LOG_SIZE_LIMIT=DISK_SIZE/2
    #let LOG_SIZE_LIMIT_GB=LOG_SIZE_LIMIT/1000000000
    #let DISK_SIZE_GB=DISK_SIZE/1000000000
    #let LOG_SIZE_LIMIT=LOG_SIZE_LIMIT_GB*1000000000
    # Check amount of system RAM (MB)
    #TOTAL_MEM=`grep MemTotal /proc/meminfo | awk '{print $2}' | sed -r 's/.{3}$//'`
    # Make RAM # human readable (GB)
    #HR_MEM=$((TOTAL_MEM / 1000))
    # Text for minimum memory check
    #MEM_TEXT="This machine currently has "$HR_MEM"GB of RAM allocated.\n\For best performance, please ensure the machine is allocated at least 3GB of RAM.\n\n\Please consult the following link for more information:\n\https://github.com/Security-Onion-Solutions/security-onion/wiki/Hardware\n\n\
    #Click 'No' to stop setup and adjust the amount of RAM allocated to this machine.\n\
    #Otherwise, click 'Yes' to continue."

  fi


##MASTER
# Add salt-key to sudoers file for socore with no password required

# They did not want to do the install
else
    exit
fi
