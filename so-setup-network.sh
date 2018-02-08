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


HOSTNAME=$(cat /etc/hostname)

# Check for prerequisites
if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run using sudo!"
        exit 1
fi

if (whiptail --title "Security Onion Setup" --yesno "Are you sure you want to install Security Onion over the internet?" 8 78) then

	# Let folks know they need their management interface already set up.
	whiptail --title "Security Onion Setup" --msgbox "Since this is a network install we assume the management interface, DNS, Hostname, etc are already set up. You must hit OK to continue." 8 78

  # What kind of install are we doing?
  INSTALLTYPE=$(whiptail --title "Security Onion Setup" --radiolist \
  "Choose Install Type:" 20 78 4 \
  "EVALMODE" "Evaluate all the things" ON \
  "SENSORONLY" "Sensor join existing grid" OFF \
  "MASTERONLY" "Start a new grid with no sensor running on it" OFF \
  "MASTERSENSOR" "Start a new grid with a sensor" OFF 3>&1 1>&2 2>&3 )

  # Get list of NICS if it isn't master only
  if [ $INSTALLTYPE != 'MASTERONLY' ]; then
    # Another option: cat /proc/net/dev | awk -F: '{print $1}' | grep -v  'lo\|veth\|br\|dock\|Inter\|byte'
    NICS=$(ip link | awk -F: '$0 !~ "lo|vir|veth|br|docker|wl|^[^0-9]"{print $2 " \"" "Interface" "\"" " OFF"}')

    # Pick which interface you want to use as the Management
  	MNIC=$(whiptail --title "NIC Setup" --radiolist "Please select your management NIC" 20 78 12 ${NICS[@]} 3>&1 1>&2 2>&3 )

    # Filter out the management NIC from the monitor NICs
    FNICS=$(ip link | grep -vw $MNIC | awk -F: '$0 !~ "lo|vir|veth|br|docker|wl|^[^0-9]"{print $2 " \"" "Interface" "\"" " OFF"}')
	  BNICS=$(whiptail --title "NIC Setup" --checklist "Please add NICs to the Monitor Interfave" 20 78 12 ${FNICS[@]} 3>&1 1>&2 2>&3 )
  fi

  if [ $INSTALLTYPE == 'SENSORONLY' ]; then

    # Get the master server for the install
    MASTERSRV=$(whiptail --title "Enter your Master Server IP Address" --inputbox 10 60 1.2.3.4 3>&1 1>&2 2>&3)

  fi

  # Time to get asnwers to questions so we can fill out the pillar file
  if [ $INSTALLTYPE != 'MASTERONLY' ]; then
    NIDS=$(whiptail --title "Security Onion Setup" --radiolist \
    "Choose which IDS to run:" 20 78 4 \
    "Suricata" "Evaluate all the things" ON 3>&1 1>&2 2>&3 )
    # Commented out until Snort releases 3.x
    #"Snort" "Sensor join existing grid" OFF 3>&1 1>&2 2>&3 )

    NSMSETUP=$(whiptail --title "Security Onion Setup" --radiolist \
    "What type of config would you like to use?:" 20 78 4 \
    "BASIC" "Install NSM components with recommended settings" ON \
    "ADVANCED" "Configure each component individually" OFF 3>&1 1>&2 2>&3 )

    if [ $NSMSETUP == 'BASIC' ]; then
      # Calculate LB_Procs
      $LBPROCS=some math

      # Calculate Suricata stuff
    fi
    if [ $NSMSETUP == 'ADVANCED' ]; then
      # Ask if this is a VM
      # Display CPU list for pinning
      $LBPROCS=Add the pins together that bro is using
      # Pin steno
      # Pin Bro
      # Pin Suricata
    fi
    # Ask how many CPUs to use for bro
  fi

  if [ $INSTALLTYPE != 'SENSORONLY' ]; then
    # Get pulled pork info
    RULESETUP=$(whiptail --title "Security Onion Setup" --radiolist \
    "What IDS rules to use?:" 20 78 4 \
    "ETOPEN" "Emerging Threats Open - no oinkcode required" ON \
    "ETPRO" "Emerging Threats PRO - requires ETPRO oinkcode" OFF \
    "TALOSET" "Snort Subscriber (Talos) ruleset and Emerging Threats NoGPL ruleset - requires Snort Subscriber oinkcode" OFF \
    "TALOS" "Snort Subscriber (Talos) ruleset only and set a Snort Subscriber policy - requires Snort Subscriber oinkcode" OFF 3>&1 1>&2 2>&3 )


  fi

  #########################
  ## Do all the things!! ##
  #########################

  # Copy over the SSH key
  if [ $INSTALLTYPE == 'SENSORONLY' ]; then
    # Generate SSH Key
    cat /dev/zero | ssh-keygen -t rsa -q -N ""

    #Copy the key over to the master
    ssh-copy-id socore@MASTERSRV
  fi

  # Detect Base OS
  if [ -f /etc/redhat-release ]; then
    OS=centos
  elif [ -f /etc/os-release ]; then
    OS=ubuntu
  else
    echo "We were unable to determine if you are using a supported OS."
    exit
  fi

  # Create bond interface
  if [ $INSTALLTYPE != 'MASTERONLY' ]; then
    echo "Setting up Bond"
  fi

  # Install Updates and the Salt Package
  if [ $OS == 'centos' ]; then
    ADDUSER=adduser
    yum -y install https://repo.saltstack.com/yum/redhat/salt-repo-latest-2.el7.noarch.rpm
    yum clean expire-cache
    yum -y install salt-minion
    if [ $INSTALLTYPE != 'SENSORONLY' ]; then
      yum -y install salt-master
    fi
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

    if [ $INSTALLTYPE != 'SENSORONLY' ]; then
      apt-get -y install salt-master
    fi
  fi

  # Create so-core user
  mkdir -p /opt/so/conf

  # Create the salt directories if this isn't a stadnalone sensor
  if [ $INSTALLTYPE != 'SENSORONLY' ]; then
    mkdir -p /opt/so/saltstack/salt
    mkdir -p /opt/so/saltstack/pillar
    cp -Rv pillar/* /opt/so/saltstack/pillar/
    cp -Rv salt/* /opt/so/saltstack/salt/
  fi

  # Add socore user to the system
  groupadd --gid 939 socore
  $ADDUSER --uid 939 --gid 939 --home-dir /opt/so --no-create-home socore

  chown -R 939:939 /opt/so

  # Add the grain on the sensor

  # Create the salt goodness
  if [ $INSTALLTYPE == 'SENSORONLY' ]; then

    # Create the grains file for the sensor
    touch /etc/salt/grains
    echo "role: so-sensor" >> /etc/salt/grains

    # Start the salt agent
    service salt-minion start

    # Do a checkin so the key gets there. Need to add some error checking here
    salt-call state.highstate

    # Create the pillar file for the sensor
    touch /tmp/$HOSTNAME.sls
    echo "sensor:" > /tmp/$HOSTNAME.sls
    echo "  interface: bond0" >> /tmp/$HOSTNAME.sls
    echo "  lbprocs: $LBPROCS" >> /tmp/$HOSTNAME.sls

    # SCP the pillar file to the master
    scp /tmp/$HOSTNAME.sls socore@$MASTERSRV:/opt/so/saltstack/pillar/sensors/

    # Accept the key on the master
    ssh socore@$MASTERSRV 'sudo salt-key -qa $HOSTNAME'
    # Grab the ssl key for lumberjack from the master
    scp socore@$MASTERSRV:/some/path /some/path


  fi

  # Do that same thing on all the others but drop em into the right place
  if [ $INSTALLTYPE == 'MASTERONLY' ]; then

    # Create the grains file for the Master
    touch /etc/salt/grains
    echo "role: so-master" >> /etc/salt/grains

    # Set up the minion to talk to itself
    echo "master: $HOSTNAME" > /etc/salt/minion

    # Copy the master config over
    cp files/master /etc/salt/master
    # Comment this out for now
    # chown -R socore:socore /etc/salt

    # Start salt master and minion
    service salt-master restart
    service salt-minion restart

    # Create the pillar
    touch /opt/so/saltstack/pillar/masters/$HOSTNAME.sls

    salt-call state.highstate
    salt-key -qya $HOSTNAME
    salt-call state.highstate

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
