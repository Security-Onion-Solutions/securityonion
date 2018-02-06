#!/bin/bash

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
    # Set password for socore

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

  # Install Updates and the Docker Package
  if [ $OS == 'centos']; then
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
    # grab the version from the os-release file
    UVER=$(grep VERSION_ID /etc/os-release | awk)
    wget -O - https://repo.saltstack.com/apt/ubuntu/$UVER/amd64/latest/SALTSTACK-GPG-KEY.pub | apt-key add -
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
  fi

  # Add socore user to the system
  groupadd --gid 939 socore
  $ADDUSER --uid 939 --gid 939 --home-dir /opt/so --no-create-home socore

  chown -R 939:939 /opt/so

  # Add the grain on the sensor

  # Create the salt goodness
  if [ $INSTALLTYPE == 'SENSORONLY' ]; then

    # Create the grains file for the sensor
    touch /etc/salt/grain
    echo "grains:" > /etc/salt/grains
    echo "  role: so-sensor" >> /etc/salt/gains

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

##MASTER
# Add salt-key to sudoers file for socore with no password required

# They did not want to do the install
else
    exit
fi
