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

bro_calculate_lbprocs() {
  #Calculate total lbprocs for basic install
  local CORES4BRO=$(( $CPUCORES/2 ))
  LBPROCS=$(printf "%.0f\n" $CORES4BRO)
}

bro_pins(){
  echo "Bro Pins will go here"
}

accept_salt_key_local() {
  # Accept the key
  salt-key -ya $HOSTNAME
}

accept_salt_key_remote() {
  # Accept the key
  ssh socore@$MASTERSRV 'sudo salt-key -ya $HOSTNAME'

}

add_socore_user_master() {
  groupadd --gid 939 socore
  $ADDUSER --uid 939 --gid 939 --home-dir /opt/so socore
  passwd socore
}

add_socore_user_notmaster() {
  # Add socore user to the system. Probably not a bad idea to make system user
  groupadd --gid 939 socore
  $ADDUSER --uid 939 --gid 939 --home-dir /opt/so --no-create-home socore

}

chown_salt_master() {
  # Chown the salt dirs
  chown -R socore:socore /opt/so
}
configure_minion() {
  local TYPE=$1

  touch /etc/salt/grains
  echo "role: so-$TYPE" > /etc/salt/grains
  if [ $TYPE == 'master' ]; then
    echo "master: $HOSTNAME" > /etc/salt/minion
  else
    echo "master: $MASTER" > /etc/salt/minion
  fi

  service salt-minion restart
}

copy_master_config() {
  cp files/master /etc/salt/master
  service salt-master restart
}

copy_minion_pillar() {
  local TYPE=$1

  if [ $TYPE = 'STORAGENODE' ]; then
    PLOC="nodes"
  else
    PLOC="sensors"
  fi

  # Copy over the pillar
  scp /tmp/$HOSTNAME.sls /opt/so/saltstack/pillar/$PLOC/

  }

configure_sensor_pillar() {

  # Create the pillar file for the sensor
  touch /tmp/$HOSTNAME.sls
  echo "sensors:" > /tmp/$HOSTNAME.sls
  echo "  interface: bond0" >> /tmp/$HOSTNAME.sls
  # Need to add logic here to determine if you are pinning or not or standalone

  echo "  bro_lbprocs: $LBPROCS" >> /tmp/$HOSTNAME.sls
  # Need to add pins loop

}

copy_ssh_key() {
  # Generate and copy SSH key
  mkdir -p ~/.ssh
  cat /dev/zero | ssh-keygen -f ~/.ssh/so.key -t rsa -q -N ""
  chown -R $SUDO_USER:$SUDO_USER ~/.ssh
  #Copy the key over to the master
  sudo ssh-copy-id -i ~/.ssh/so.key socore@$MSRV
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

#create_socore_password() {
  # Enter a password for socore
#}

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

#disk_space() {
  # Give me Disk Space
#}

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
  if [ $OS == 'centos' ]; then
    yum -y install salt-master
  else
    apt install -y salt-master
  fi

  copy_master_config
  # If Centos Enable the service
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
  echo "  nids_rules: $RULESETUP" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  oinkcode: $OINKCODE" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls

node_pillar() {
  # Create the node pillar
  touch /tmp/$HOSTNAME.sls
  echo "node:" > /tmp/$HOSTNAME.sls
  echo "  esaccessip: 127.0.0.1" >> /tmp/$HOSTNAME.sls
  echo "  esheap: $NODEESHEAP" >> /tmp/$HOSTNAME.sls
  echo "  esclustername: {{ grains.host }}" >> /tmp/$HOSTNAME.sls
  echo "  lsheap: $NODELSHEAP" >> /tmp/$HOSTNAME.sls
  echo "  lsaccessip: 127.0.0.1" >> /tmp/$HOSTNAME.sls
  echo "  ls_pipeline_workers: $LSPIPELINEWORKERS" >> /tmp/$HOSTNAME.sls
  echo "  ls_pipeline_batch_size: $LSPIPELINEBATCH" >> /tmp/$HOSTNAME.sls
  echo "  ls_input_threads: $LSINPUTTHREADS" >> /tmp/$HOSTNAME.sls
  echo "  ls_batch_count: $LSINPUTBATCHCOUNT" >> /tmp/$HOSTNAME.sls
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

salt_checkin() {
  salt-call state.highstate
}

salt_checkin_message() {
  echo "####################################################"
  echo "##                                                ##"
  echo "##        Applying and Installing everything      ##"
  echo "##             (This will take a while)           ##"
  echo "##                                                ##"
  echo "####################################################"
}

salt_master_directories() {
  # Create salt directories
  mkdir -p /opt/so/saltstack/salt
  mkdir -p /opt/so/saltstack/pillar
  cp -R pillar/* /opt/so/saltstack/pillar/
  cp -R salt/* /opt/so/saltstack/salt/
}

update_sudoers() {

  # Update Sudoers
  echo "socore ALL=(ALL) NOPASSWD:/usr/bin/salt-key" | sudo tee -a /etc/sudoers

}

###########################################
##                                       ##
##         Whiptail Menu Section         ##
##                                       ##
###########################################

whiptail_bro_pins() {

  BROPINS=$(whiptail --noitem --title "Pin Bro CPUS" --checklist "Please Select Cores to Pin Bro to" 20 78 12 ${LISTCORES[@]} 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus


}

whiptail_bond_nics() {

  BNICS=$(whiptail --title "NIC Setup" --checklist "Please add NICs to the Monitor Interface" 20 78 12 ${FNICS[@]} 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_cancel() {
  whiptail --title "Security Onion Setup" --msgbox "Cancelling Setup. No changes have been made." 8 78
  exit
}

whiptail_check_exitstatus() {
  if [ $1 == '1' ]; then
    echo " They hit cancel"
    whiptail_cancel
  fi
}
whiptail_install_type() {

  # What kind of install are we doing?
  INSTALLTYPE=$(whiptail --title "Security Onion Setup" --radiolist \
  "Choose Install Type:" 20 78 4 \
  "EVALMODE" "Evaluate all the things" ON \
  "SENSORONLY" "Create a forward only sensor" OFF \
  "MASTERONLY" "Start a new grid" OFF \
  "STORAGENODE" "Add a Storage Node" OFF 3>&1 1>&2 2>&3 )

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
  "Suricata" "Evaluate all the things" ON 3>&1 1>&2 2>&3 )

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
  "Enter your Master Server Name or IP Address" 10 60 XXXX 3>&1 1>&2 2>&3)

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
  NODEESHEAP=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter ES Heap Size: \n \n(Recommended value is pre-populated)" 10 60 $ES_HEAP_SIZE 3>&1 1>&2 2>&3)

}

whiptail_node_ls_heap() {

  ls_heapsize
  NODELSHEAP=$(whiptail --title "Security Onion Setup" --inputbox \
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

  NSMSETUP=$(whiptail --noitem --title "Security Onion Setup" --radiolist \
  "What type of config would you like to use?:" 20 78 4 \
  "BASIC" "Install NSM components with recommended settings" ON \
  "ADVANCED" "Configure each component individually" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}
whiptail_setup_complete() {
  whiptail --title "Security Onion Setup" --msgbox "Finished installing this as an $INSTALLTYPE. A reboot is recommended." 8 78
  exit
}
whiptail_you_sure() {

  whiptail --title "Security Onion Setup" --yesno "Are you sure you want to install Security Onion over the internet?" 8 78

}
# End Functions

# Check for prerequisites
echo "Checking for Root"
got_root
echo "Detecting OS"
detect_os
if [ $OS == ubuntu ]; then
  # Override the horrible Ubuntu whiptail color pallete
  update-alternatives --set newt-palette /etc/newt/palette.original
fi

# Question Time

if (whiptail_you_sure) then

	# Let folks know they need their management interface already set up.
	whiptail_network_notice

  # What kind of install are we doing?
  whiptail_install_type

  if [ $INSTALLTYPE == 'MASTERONLY' ]; then

    # Pick the Management NIC
    whiptail_management_nic
    # Select Snort or Suricata
    whiptail_nids
    # Pick your Ruleset
    whiptail_rule_setup

    # Get the code if it isn't ET Open
    if [ $RULESETUP != 'ETOPEN' ]; then
      # Get the code
      whiptail_oinkcode
    fi

    # Last Chance to back out
    whiptail_make_changes

    # Install salt and dependencies
    saltify
    configure_minion master
    install_master
    salt_master_directories
    echo ""
    echo "**** Please set a password for socore. You will use this password when setting up other Nodes/Sensors"
    echo ""
    add_socore_user_master
    update_sudoers
    chown_salt_master
    es_heapsize
    ls_heapsize
    echo "generating the master pillar"
    master_pillar
    # Do a checkin to push the key up
    salt_checkin
    # Accept the Master Key
    accept_salt_key_local
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
    whiptail_nids
    whiptail_sensor_config
    if [ $NSMSETUP == 'ADVANCED' ]; then
      whiptail_bro_pins
    fi
    configure_minion
    copy_ssh_key
    create_bond
    saltify
    configure_minion sensors
    copy_ssh_key
    copy_minion_pillar SENSORONLY

  fi
  if [ $INSTALLTYPE == 'EVALMODE' ]; then
    whiptail_management_nic
    filter_nics
    whiptail_bond_nics
    whiptail_management_server
    whiptail_nids
    whiptail_sensor_config
    configure_minion
    copy_ssh_key
    create_bond
    saltify
    configure_minion sensors
    copy_ssh_key
    copy_minion_pillar SENSORONLY
  fi
  if [ $INSTALLTYPE == 'STORAGENODE' ]; then
    whiptail_management_nic
    echo "Why isn't this working"
    whiptail_management_server
    whiptail_node_advanced
    if [ $NODESETUP == 'NODEADVANCED' ]; then
      whiptail_node_es_heap
      whiptail_node_ls_heap
      whiptail_node_ls_pipeline_worker
      whiptail_node_ls_pipline_batchsize
      whiptail_node_ls_input_threads
      whiptail_node_ls_input_batch_count
    else
      NODEESHEAP=$ES_HEAP_SIZE
      NODELSHEAP=$LS_HEAP_SIZE
      LSPIPELINEWORKERS=1
      LSPIPELINEBATCH=125
      LSINPUTTHREADS=1
      LSINPUTBATCHCOUNT=125
    fi
    configure_minion node
    copy_ssh_key
    #saltify
    #configure_minion node
    #copy_ssh_key
    #copy_minion_pillar STORAGENODE
  fi

else
    exit
fi
