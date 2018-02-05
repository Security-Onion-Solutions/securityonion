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
    # Ask what IDS to use
    # Ask how many CPUs to use for bro
  fi

  if [ $INSTALLTYPE != 'SENSORONLY' ]; then
    # Get pulled pork info
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
  mkdir -p /opt/so/saltstack/salt
  mkdir -p /opt/so/saltstack/pillar
  groupadd --gid 939 socore
  $ADDUSER --uid 939 --gid 939 --home-dir /opt/so --no-create-home socore

  chown -R 939:939 /opt/so

  # Add the grain
  # Create the sls file
  if [ $INSTALLTYPE == 'SENSORONLY' ]; then

    #Do the grains file

    service salt-minion start
    salt-call state.highstate
    touch /tmp/$HOSTNAME.sls
    echo "sensor:" > /tmp/$HOSTNAME.sls
    echo "  interface: bond0" >> /tmp/$HOSTNAME
    echo "  lbprocs: $LBPROCS" >> /tmp/$HOSTNAME

    # SCP the pillar file to the master
    scp /tmp/$HOSTNAME.sls socore@$MASTERSRV:/opt/so/saltstack/pillar/sensors/

    # Accept the key on the master
    ssh socore@$MASTERSRV 'sudo salt-key -qa $HOSTNAME'

  fi
  
##MASTER
# Add salt-key to suduers file for socore with no password required

# They did not want to do the install
else
    exit
fi
