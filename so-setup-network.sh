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
RANDOMUID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
NODE_ES_PORT="9200"

# End Global Variable Section

# Functions

accept_salt_key_local() {

  # Accept the key locally on the master
  salt-key -ya $HOSTNAME

}

accept_salt_key_remote() {

  # Delete the key just in case.
  ssh -i /root/.ssh/so.key socore@$MSRV sudo salt-key -d $HOSTNAME -y
  salt-call state.apply ca
  ssh -i /root/.ssh/so.key socore@$MSRV sudo salt-key -a $HOSTNAME -y

}

add_master_hostfile() {
  # Pop up an input to get the IP address
  local MSRVIP=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter your Master Server IP Address" 10 60 X.X.X.X 3>&1 1>&2 2>&3)

  # Add the master to the host file if it doesn't resolve
  echo "$MSRVIP   $MSRV" >> /etc/hosts
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

#add_wazuh_users() {

  # REMARKING FOR NOW -- ADDING VIA init.sls
  #if [ $OS == 'centos' ]; then
  #  local ADDUSER=adduser
  #else
  #  local ADDUSER=useradd
  #fi

  #groupadd --gid 945 ossec
  #$ADDUSER --uid 943 --gid 945 --home-dir /opt/so/wazuh --no-create-home ossecm
  #$ADDUSER --uid 944 --gid 945 --home-dir /opt/so/wazuh --no-create-home ossecr
  #$ADDUSER --uid 945 --gid 945 --home-dir /opt/so/wazuh --no-create-home ossec

#}

# Create an auth pillar so that passwords survive re-install
auth_pillar(){

  if [ ! -f /opt/so/saltstack/pillar/auth.sls ]; then
    echo "Creating Auth Pillar"
    mkdir -p /opt/so/saltstack/pillar
    echo "auth:" >> /opt/so/saltstack/pillar/auth.sls
    echo "  mysql: $MYSQLPASS" >> /opt/so/saltstack/pillar/auth.sls
    echo "  fleet: $FLEETPASS" >> /opt/so/saltstack/pillar/auth.sls
  fi

}

# Enable Bro Logs
bro_logs_enabled() {

  echo "brologs:" > pillar/brologs.sls
  echo "  enabled:" >> pillar/brologs.sls

  if [ $MASTERADV == 'ADVANCED' ]; then
    for BLOG in ${BLOGS[@]}; do
      echo "    - $BLOG" | tr -d '"' >> pillar/brologs.sls
    done
  else
    echo "    - conn" >> pillar/brologs.sls
    echo "    - dce_rpc" >> pillar/brologs.sls
    echo "    - dhcp" >> pillar/brologs.sls
    echo "    - dhcpv6" >> pillar/brologs.sls
    echo "    - dnp3" >> pillar/brologs.sls
    echo "    - dns" >> pillar/brologs.sls
    echo "    - dpd" >> pillar/brologs.sls
    echo "    - files" >> pillar/brologs.sls
    echo "    - ftp" >> pillar/brologs.sls
    echo "    - http" >> pillar/brologs.sls
    echo "    - intel" >> pillar/brologs.sls
    echo "    - irc" >> pillar/brologs.sls
    echo "    - kerberos" >> pillar/brologs.sls
    echo "    - modbus" >> pillar/brologs.sls
    echo "    - mqtt" >> pillar/brologs.sls
    echo "    - notice" >> pillar/brologs.sls
    echo "    - ntlm" >> pillar/brologs.sls
    echo "    - openvpn" >> pillar/brologs.sls
    echo "    - pe" >> pillar/brologs.sls
    echo "    - radius" >> pillar/brologs.sls
    echo "    - rfb" >> pillar/brologs.sls
    echo "    - rdp" >> pillar/brologs.sls
    echo "    - signatures" >> pillar/brologs.sls
    echo "    - sip" >> pillar/brologs.sls
    echo "    - smb_files" >> pillar/brologs.sls
    echo "    - smb_mapping" >> pillar/brologs.sls
    echo "    - smtp" >> pillar/brologs.sls
    echo "    - snmp" >> pillar/brologs.sls
    echo "    - software" >> pillar/brologs.sls
    echo "    - ssh" >> pillar/brologs.sls
    echo "    - ssl" >> pillar/brologs.sls
    echo "    - syslog" >> pillar/brologs.sls
    echo "    - telnet" >> pillar/brologs.sls
    echo "    - tunnel" >> pillar/brologs.sls
    echo "    - weird" >> pillar/brologs.sls
    echo "    - mysql" >> pillar/brologs.sls
    echo "    - socks" >> pillar/brologs.sls
    echo "    - x509" >> pillar/brologs.sls
  fi
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

checkin_at_boot() {
  echo "startup_states: highstate" >> /etc/salt/minion
}

chown_salt_master() {

  # Chown the salt dirs on the master for socore
  chown -R socore:socore /opt/so

}

clear_master() {
  # Clear out the old master public key in case this is a re-install.
  # This only happens if you re-install the master.
  if [ -f /etc/salt/pki/minion/minion_master.pub ]; then
    rm /etc/salt/pki/minion/minion_master.pub
    service salt-minion restart
  fi

}

configure_minion() {

  # You have to pass the TYPE to this function so it knows if its a master or not
  local TYPE=$1
  echo "Configuring minion type as $TYPE"
  touch /etc/salt/grains
  echo "role: so-$TYPE" > /etc/salt/grains
  if [ $TYPE == 'master' ] || [ $TYPE == 'eval' ]; then
    echo "master: $HOSTNAME" > /etc/salt/minion
    echo "id: $HOSTNAME" >> /etc/salt/minion
    echo "mysql.host: '$MAINIP'" >> /etc/salt/minion
    echo "mysql.port: 3306" >> /etc/salt/minion
    echo "mysql.user: 'root'" >> /etc/salt/minion
    if [ ! -f /opt/so/saltstack/pillar/auth.sls ]; then
      echo "mysql.pass: '$MYSQLPASS'" >> /etc/salt/minion
    else
      OLDPASS=$(cat /opt/so/saltstack/pillar/auth.sls | grep mysql | awk {'print $2'})
      echo "mysql.pass: '$OLDPASS'" >> /etc/salt/minion
    fi
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
  scp -v -i /root/.ssh/so.key $TMP/$HOSTNAME.sls socore@$MSRV:/opt/so/saltstack/pillar/$TYPE/$HOSTNAME.sls

  }

copy_ssh_key() {

  # Generate SSH key
  mkdir -p /root/.ssh
  cat /dev/zero | ssh-keygen -f /root/.ssh/so.key -t rsa -q -N ""
  chown -R $SUDO_USER:$SUDO_USER /root/.ssh
  #Copy the key over to the master
  ssh-copy-id -f -i /root/.ssh/so.key socore@$MSRV

}

create_bond() {

  # Create the bond interface
  echo "Setting up Bond"

  # Set the MTU
  if [ $NSMSETUP != 'ADVANCED' ]; then
    MTU=1500
  fi

  # Do something different based on the OS
  if [ $OS == 'centos' ]; then
    modprobe --first-time bonding
    touch /etc/sysconfig/network-scripts/ifcfg-bond0
    echo "DEVICE=bond0" > /etc/sysconfig/network-scripts/ifcfg-bond0
    echo "NAME=bond0" >> /etc/sysconfig/network-scripts/ifcfg-bond0
    echo "Type=Bond" >> /etc/sysconfig/network-scripts/ifcfg-bond0
    echo "BONDING_MASTER=yes" >> /etc/sysconfig/network-scripts/ifcfg-bond0
    echo "BOOTPROTO=none" >> /etc/sysconfig/network-scripts/ifcfg-bond0
    echo "BONDING_OPTS=\"mode=0\"" >> /etc/sysconfig/network-scripts/ifcfg-bond0
    echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/ifcfg-bond0
    echo "MTU=$MTU" >> /etc/sysconfig/network-scripts/ifcfg-bond0

    # Create Bond configs for the selected monitor interface
    for BNIC in ${BNICS[@]}; do
      BONDNIC="${BNIC%\"}"
      BONDNIC="${BONDNIC#\"}"
      sed -i 's/ONBOOT=no/ONBOOT=yes/g' /etc/sysconfig/network-scripts/ifcfg-$BONDNIC
      echo "MASTER=bond0" >> /etc/sysconfig/network-scripts/ifcfg-$BONDNIC
      echo "SLAVE=yes" >> /etc/sysconfig/network-scripts/ifcfg-$BONDNIC
      echo "MTU=$MTU" >> /etc/sysconfig/network-scripts/ifcfg-$BONDNIC
    done
    nmcli con reload
    systemctl restart network

  else

    # Need to add 17.04 support still
    apt-get -y install ifenslave
    echo "bonding" >> /etc/modules
    modprobe bonding

    local LBACK=$(awk '/auto lo/,/^$/' /etc/network/interfaces)
    local MINT=$(awk "/auto $MNIC/,/^$/" /etc/network/interfaces)

    # Backup and create a new interface file
    cp /etc/network/interfaces /etc/network/interfaces.sosetup
    echo "source /etc/network/interfaces.d/*" > /etc/network/interfaces
    echo "" >> /etc/network/interfaces

    # Let's set up the new interface file
    # Populate lo and create file for the management interface
    IFS=$'\n'
    for line in $LBACK
    do
      echo $line >> /etc/network/interfaces
    done

    IFS=$'\n'
    for line in $MINT
    do
      echo $line >> /etc/network/interfaces.d/$MNIC
    done

    # Create entries for each interface that is part of the bond.
    for BNIC in ${BNICS[@]}; do

      BNIC=$(echo $BNIC |  cut -d\" -f2)
      echo "auto $BNIC" >> /etc/network/interfaces.d/$BNIC
      echo "iface $BNIC inet manual" >> /etc/network/interfaces.d/$BNIC
      echo "  up ip link set \$IFACE promisc on arp off up" >> /etc/network/interfaces.d/$BNIC
      echo "  down ip link set \$IFACE promisc off down" >> /etc/network/interfaces.d/$BNIC
      echo "  post-up ethtool -G \$IFACE rx 4096; for i in rx tx sg tso ufo gso gro lro; do ethtool -K \$IFACE \$i off; done" >> /etc/network/interfaces.d/$BNIC
      echo "  post-up echo 1 > /proc/sys/net/ipv6/conf/\$IFACE/disable_ipv6" >> /etc/network/interfaces.d/$BNIC
      echo "  bond-master bond0" >> /etc/network/interfaces.d/$BNIC
      echo "  mtu $MTU" >> /etc/network/interfaces.d/$BNIC

    done

    BN=("${BNICS[@]//\"/}")

    echo "auto bond0" > /etc/network/interfaces.d/bond0
    echo "iface bond0 inet manual" >> /etc/network/interfaces.d/bond0
    echo "  bond-mode 0" >> /etc/network/interfaces.d/bond0
    echo "  bond-slaves $BN" >> /etc/network/interfaces.d/bond0
    echo "  mtu $MTU" >> /etc/network/interfaces.d/bond0
    echo "  up ip link set \$IFACE promisc on arp off up" >> /etc/network/interfaces.d/bond0
    echo "  down ip link set \$IFACE promisc off down" >> /etc/network/interfaces.d/bond0
    echo "  post-up ethtool -G \$IFACE rx 4096; for i in rx tx sg tso ufo gso gro lro; do ethtool -K \$IFACE \$i off; done" >> /etc/network/interfaces.d/bond0
    echo "  post-up echo 1 > /proc/sys/net/ipv6/conf/\$IFACE/disable_ipv6" >> /etc/network/interfaces.d/bond0
  fi

}

detect_os() {

  # Detect Base OS
  echo "Detecting Base OS"
  if [ -f /etc/redhat-release ]; then
    OS=centos
    yum -y install bind-utils
  elif [ -f /etc/os-release ]; then
    OS=ubuntu
  else
    echo "We were unable to determine if you are using a supported OS."
    exit
  fi

}

docker_install() {

  if [ $OS == 'centos' ]; then
    yum clean expire-cache
    yum -y install yum-utils device-mapper-persistent-data lvm2 openssl
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    yum -y update
    yum -y install docker-ce docker-python python-docker
    docker_registry
    echo "Restarting Docker"
    systemctl restart docker
    systemctl enable docker

  else
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

generate_passwords(){
  # Generate Random Passwords for Things
  MYSQLPASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 20 | head -n 1)
  FLEETPASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 20 | head -n 1)
}

get_filesystem_nsm(){
  FSNSM=$(df /nsm | awk '$3 ~ /[0-9]+/ { print $2 * 1000 }')
}

get_log_size_limit() {

  DISK_SIZE_K=`df /nsm |grep -v "^Filesystem" | awk '{print $2}'`
  PERCENTAGE=85
  DISK_SIZE=DISK_SIZE_K*1000
  PERCENTAGE_DISK_SPACE=`echo $(($DISK_SIZE*$PERCENTAGE/100))`
  LOG_SIZE_LIMIT=$(($PERCENTAGE_DISK_SPACE/1000000000))

}

get_filesystem_root(){
  FSROOT=$(df / | awk '$3 ~ /[0-9]+/ { print $2 * 1000 }')
}

get_main_ip() {

  # Get the main IP address the box is using
  MAINIP=$(ip route get 1 | awk '{print $NF;exit}')
  MAININT=$(ip route get 1 | awk '{print $5;exit}')

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
  rm -rf /root/installtmp

}

install_prep() {

  # Create a tmp space that isn't in /tmp
  mkdir /root/installtmp
  TMP=/root/installtmp

}

install_master() {

  # Install the salt master package
  if [ $OS == 'centos' ]; then
    yum -y install salt-master wget

    # Create a place for the keys for Ubuntu minions
    mkdir -p /opt/so/gpg
    wget --inet4-only -O /opt/so/gpg/SALTSTACK-GPG-KEY.pub https://repo.saltstack.com/apt/ubuntu/16.04/amd64/latest/SALTSTACK-GPG-KEY.pub
    wget --inet4-only -O /opt/so/gpg/docker.pub https://download.docker.com/linux/ubuntu/gpg
    wget --inet4-only -O /opt/so/gpg/GPG-KEY-WAZUH https://packages.wazuh.com/key/GPG-KEY-WAZUH

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
  echo "  mainip: $MAINIP" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  mainint: $MAININT" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  esheap: $ES_HEAP_SIZE" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  esclustername: {{ grains.host }}" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  if [ $INSTALLTYPE == 'EVALMODE' ]; then
    echo "  freq: 1" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
    echo "  domainstats: 1" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
    echo "  ls_pipeline_batch_size: 125" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
    echo "  ls_input_threads: 1" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
    echo "  ls_batch_count: 125" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
    echo "  mtu: 1500" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
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
  #echo "  access_key: $ACCESS_KEY" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  #echo "  access_secret: $ACCESS_SECRET" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  es_port: $NODE_ES_PORT" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  log_size_limit: $LOG_SIZE_LIMIT" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  echo "  cur_close_days: $CURCLOSEDAYS" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  #echo "  mysqlpass: $MYSQLPASS" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls
  #echo "  fleetpass: $FLEETPASS" >> /opt/so/saltstack/pillar/masters/$HOSTNAME.sls

  }

master_static() {

  # Create a static file for global values
  touch /opt/so/saltstack/pillar/static.sls

  echo "static:" > /opt/so/saltstack/pillar/static.sls
  echo "  hnmaster: $HNMASTER" >> /opt/so/saltstack/pillar/static.sls
  echo "  ntpserver: $NTPSERVER" >> /opt/so/saltstack/pillar/static.sls
  echo "  proxy: $PROXY" >> /opt/so/saltstack/pillar/static.sls
  echo "  broversion: $BROVERSION" >> /opt/so/saltstack/pillar/static.sls
  echo "  ids: $NIDS" >> /opt/so/saltstack/pillar/static.sls
  echo "  masterip: $MAINIP" >> /opt/so/saltstack/pillar/static.sls
  if [[ $MASTERUPDATES == 'MASTER' ]]; then
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
  echo "  mainint: $MAININT" >> $TMP/$HOSTNAME.sls
  echo "  esheap: $NODE_ES_HEAP_SIZE" >> $TMP/$HOSTNAME.sls
  echo "  esclustername: {{ grains.host }}" >> $TMP/$HOSTNAME.sls
  echo "  lsheap: $NODE_LS_HEAP_SIZE" >> $TMP/$HOSTNAME.sls
  echo "  ls_pipeline_workers: $LSPIPELINEWORKERS" >> $TMP/$HOSTNAME.sls
  echo "  ls_pipeline_batch_size: $LSPIPELINEBATCH" >> $TMP/$HOSTNAME.sls
  echo "  ls_input_threads: $LSINPUTTHREADS" >> $TMP/$HOSTNAME.sls
  echo "  ls_batch_count: $LSINPUTBATCHCOUNT" >> $TMP/$HOSTNAME.sls
  echo "  es_shard_count: $SHARDCOUNT" >> $TMP/$HOSTNAME.sls
  echo "  node_type: $NODETYPE" >> $TMP/$HOSTNAME.sls
  echo "  es_port: $NODE_ES_PORT" >> $TMP/$HOSTNAME.sls
  echo "  log_size_limit: $LOG_SIZE_LIMIT" >> $TMP/$HOSTNAME.sls
  echo "  cur_close_days: $CURCLOSEDAYS" >> $TMP/$HOSTNAME.sls

}

saltify() {

  # Install updates and Salt
  if [ $OS == 'centos' ]; then
    ADDUSER=adduser

    if [ $INSTALLTYPE == 'MASTERONLY' ] || [ $INSTALLTYPE == 'EVALMODE' ]; then
      yum -y install https://repo.saltstack.com/yum/redhat/salt-repo-latest-2.el7.noarch.rpm

    else

      if [ $MASTERUPDATES == 'MASTER' ]; then

        # Create the GPG Public Key for the Salt Repo
        echo "-----BEGIN PGP PUBLIC KEY BLOCK-----" > /etc/pki/rpm-gpg/saltstack-signing-key
        echo "Version: GnuPG v2.0.22 (GNU/Linux)" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "mQENBFOpvpgBCADkP656H41i8fpplEEB8IeLhugyC2rTEwwSclb8tQNYtUiGdna9" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "m38kb0OS2DDrEdtdQb2hWCnswxaAkUunb2qq18vd3dBvlnI+C4/xu5ksZZkRj+fW" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "tArNR18V+2jkwcG26m8AxIrT+m4M6/bgnSfHTBtT5adNfVcTHqiT1JtCbQcXmwVw" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "WbqS6v/LhcsBE//SHne4uBCK/GHxZHhQ5jz5h+3vWeV4gvxS3Xu6v1IlIpLDwUts" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "kT1DumfynYnnZmWTGc6SYyIFXTPJLtnoWDb9OBdWgZxXfHEcBsKGha+bXO+m2tHA" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "gNneN9i5f8oNxo5njrL8jkCckOpNpng18BKXABEBAAG0MlNhbHRTdGFjayBQYWNr" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "YWdpbmcgVGVhbSA8cGFja2FnaW5nQHNhbHRzdGFjay5jb20+iQE4BBMBAgAiBQJT" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "qb6YAhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRAOCKFJ3le/vhkqB/0Q" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "WzELZf4d87WApzolLG+zpsJKtt/ueXL1W1KA7JILhXB1uyvVORt8uA9FjmE083o1" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "yE66wCya7V8hjNn2lkLXboOUd1UTErlRg1GYbIt++VPscTxHxwpjDGxDB1/fiX2o" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "nK5SEpuj4IeIPJVE/uLNAwZyfX8DArLVJ5h8lknwiHlQLGlnOu9ulEAejwAKt9CU" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "4oYTszYM4xrbtjB/fR+mPnYh2fBoQO4d/NQiejIEyd9IEEMd/03AJQBuMux62tjA" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "/NwvQ9eqNgLw9NisFNHRWtP4jhAOsshv1WW+zPzu3ozoO+lLHixUIz7fqRk38q8Q" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "9oNR31KvrkSNrFbA3D89uQENBFOpvpgBCADJ79iH10AfAfpTBEQwa6vzUI3Eltqb" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "9aZ0xbZV8V/8pnuU7rqM7Z+nJgldibFk4gFG2bHCG1C5aEH/FmcOMvTKDhJSFQUx" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "uhgxttMArXm2c22OSy1hpsnVG68G32Nag/QFEJ++3hNnbyGZpHnPiYgej3FrerQJ" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "zv456wIsxRDMvJ1NZQB3twoCqwapC6FJE2hukSdWB5yCYpWlZJXBKzlYz/gwD/Fr" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "GL578WrLhKw3UvnJmlpqQaDKwmV2s7MsoZogC6wkHE92kGPG2GmoRD3ALjmCvN1E" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "PsIsQGnwpcXsRpYVCoW7e2nW4wUf7IkFZ94yOCmUq6WreWI4NggRcFC5ABEBAAGJ" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "AR8EGAECAAkFAlOpvpgCGwwACgkQDgihSd5Xv74/NggA08kEdBkiWWwJZUZEy7cK" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "WWcgjnRuOHd4rPeT+vQbOWGu6x4bxuVf9aTiYkf7ZjVF2lPn97EXOEGFWPZeZbH4" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "vdRFH9jMtP+rrLt6+3c9j0M8SIJYwBL1+CNpEC/BuHj/Ra/cmnG5ZNhYebm76h5f" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "T9iPW9fFww36FzFka4VPlvA4oB7ebBtquFg3sdQNU/MmTVV4jPFWXxh4oRDDR+8N" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "1bcPnbB11b5ary99F/mqr7RgQ+YFF0uKRE3SKa7a+6cIuHEZ7Za+zhPaQlzAOZlx" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "fuBmScum8uQTrEF5+Um5zkwC7EXTdH1co/+/V/fpOtxIg4XO4kcugZefVm5ERfVS" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "MA==" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "=dtMN" >> /etc/pki/rpm-gpg/saltstack-signing-key
        echo "-----END PGP PUBLIC KEY BLOCK-----" >> /etc/pki/rpm-gpg/saltstack-signing-key

        # Proxy is hating on me.. Lets just set it manually
        echo "[salt-latest]" > /etc/yum.repos.d/salt-latest.repo
        echo "name=SaltStack Latest Release Channel for RHEL/Centos \$releasever" >> /etc/yum.repos.d/salt-latest.repo
        echo "baseurl=https://repo.saltstack.com/yum/redhat/7/\$basearch/latest" >> /etc/yum.repos.d/salt-latest.repo
        echo "failovermethod=priority" >> /etc/yum.repos.d/salt-latest.repo
        echo "enabled=1" >> /etc/yum.repos.d/salt-latest.repo
        echo "gpgcheck=1" >> /etc/yum.repos.d/salt-latest.repo
        echo "gpgkey=file:///etc/pki/rpm-gpg/saltstack-signing-key" >> /etc/yum.repos.d/salt-latest.repo
      else
        yum -y install https://repo.saltstack.com/yum/redhat/salt-repo-latest-2.el7.noarch.rpm
      fi
    fi

    yum clean expire-cache
    yum -y install salt-minion yum-utils device-mapper-persistent-data lvm2 openssl
    yum -y update
    systemctl enable salt-minion

    # Nasty hack but required for now
    if [ $INSTALLTYPE == 'MASTERONLY' ] || [ $INSTALLTYPE == 'EVALMODE' ]; then
      yum -y install salt-master python-m2crypto salt-minion m2crypto
      systemctl enable salt-master
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
      wget --inet4-only -O /opt/so/gpg/GPG-KEY-WAZUH https://packages.wazuh.com/key/GPG-KEY-WAZUH
      # Initialize the new repos
      apt-get update >>~/sosetup.log 2>&1
      apt-get -y install salt-minion python-m2crypto >>~/sosetup.log 2>&1

    else

      # Copy down the gpg keys and install them from the master
      mkdir $TMP/gpg
      scp socore@$MSRV:/opt/so/gpg/* $TMP/gpg
      apt-key add $TMP/gpg/SALTSTACK-GPG-KEY.pub
      apt-key add $TMP/gpg/GPG-KEY-WAZUH
      echo "deb http://repo.saltstack.com/apt/ubuntu/$UVER/amd64/latest xenial main" > /etc/apt/sources.list.d/saltstack.list
      echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
      # Initialize the new repos
      apt-get update >>~/sosetup.log 2>&1
      apt-get -y install salt-minion python-m2crypto >>~/sosetup.log 2>&1

    fi

  fi

}

salt_checkin() {
  # Master State to Fix Mine Usage
  if [ $INSTALLTYPE == 'MASTERONLY' ] || [ $INSTALLTYPE == 'EVALMODE' ]; then
  echo "Building Certificate Authority"
  salt-call state.apply ca
  echo " *** Restarting Salt to fix any SSL errors. ***"
  service salt-master restart
  sleep 5
  service salt-minion restart
  sleep 15
  echo " Applyng a mine hack "
  sudo salt '*' mine.send x509.get_pem_entries glob_path=/etc/pki/ca.crt
  echo " Applying SSL state "
  salt-call state.apply ssl
  echo "Still Working... Hang in there"
  salt-call state.highstate

  else

  # Run Checkin
  salt-call state.apply ca
  salt-call state.apply ssl
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
  chmod +x /opt/so/saltstack/pillar/data/addtotab.sh
  cp -R salt/* /opt/so/saltstack/salt/

}

sensor_pillar() {

  # Create the sensor pillar
  touch $TMP/$HOSTNAME.sls
  echo "sensor:" > $TMP/$HOSTNAME.sls
  echo "  interface: bond0" >> $TMP/$HOSTNAME.sls
  echo "  mainip: $MAINIP" >> $TMP/$HOSTNAME.sls
  echo "  mainint: $MAININT" >> $TMP/$HOSTNAME.sls
  if [ $NSMSETUP == 'ADVANCED' ]; then
    echo "  bro_pins:" >> $TMP/$HOSTNAME.sls
    for PIN in $BROPINS; do
      PIN=$(echo $PIN |  cut -d\" -f2)
    echo "    - $PIN" >> $TMP/$HOSTNAME.sls
    done
    echo "  suripins:" >> $TMP/$HOSTNAME.sls
    for SPIN in $SURIPINS; do
      SPIN=$(echo $SPIN |  cut -d\" -f2)
    echo "    - $SPIN" >> $TMP/$HOSTNAME.sls
    done
  else
    echo "  bro_lbprocs: $BASICBRO" >> $TMP/$HOSTNAME.sls
    echo "  suriprocs: $BASICSURI" >> $TMP/$HOSTNAME.sls
  fi
  echo "  brobpf:" >> $TMP/$HOSTNAME.sls
  echo "  pcapbpf:" >> $TMP/$HOSTNAME.sls
  echo "  nidsbpf:" >> $TMP/$HOSTNAME.sls
  echo "  master: $MSRV" >> $TMP/$HOSTNAME.sls
  echo "  mtu: $MTU" >> $TMP/$HOSTNAME.sls
  if [ $HNSENSOR != 'inherit' ]; then
  echo "  hnsensor: $HNSENSOR" >> $TMP/$HOSTNAME.sls
  fi
  echo "  access_key: $ACCESS_KEY" >> $TMP/$HOSTNAME.sls
  echo "  access_secret: $ACCESS_SECRET" >>  $TMP/$HOSTNAME.sls

}

set_initial_firewall_policy() {

  get_main_ip
  if [ $INSTALLTYPE == 'MASTERONLY' ]; then
    printf "  - $MAINIP\n" >> /opt/so/saltstack/pillar/firewall/minions.sls
    printf "  - $MAINIP\n" >> /opt/so/saltstack/pillar/firewall/masterfw.sls
    /opt/so/saltstack/pillar/data/addtotab.sh mastertab $HOSTNAME $MAINIP $CPUCORES $RANDOMUID $MAININT $FSROOT $FSNSM
  fi

  if [ $INSTALLTYPE == 'EVALMODE' ]; then
    printf "  - $MAINIP\n" >> /opt/so/saltstack/pillar/firewall/minions.sls
    printf "  - $MAINIP\n" >> /opt/so/saltstack/pillar/firewall/masterfw.sls
    printf "  - $MAINIP\n" >> /opt/so/saltstack/pillar/firewall/forward_nodes.sls
    printf "  - $MAINIP\n" >> /opt/so/saltstack/pillar/firewall/storage_nodes.sls
    /opt/so/saltstack/pillar/data/addtotab.sh evaltab $HOSTNAME $MAINIP $CPUCORES $RANDOMUID $MAININT $FSROOT $FSNSM bond0
  fi

  if [ $INSTALLTYPE == 'SENSORONLY' ]; then
    ssh -i /root/.ssh/so.key socore@$MSRV sudo /opt/so/saltstack/pillar/firewall/addfirewall.sh minions $MAINIP
    ssh -i /root/.ssh/so.key socore@$MSRV sudo /opt/so/saltstack/pillar/firewall/addfirewall.sh forward_nodes $MAINIP
    ssh -i /root/.ssh/so.key socore@$MSRV sudo /opt/so/saltstack/pillar/data/addtotab.sh sensorstab $HOSTNAME $MAINIP $CPUCORES $RANDOMUID $MAININT $FSROOT $FSNSM bond0
  fi

  if [ $INSTALLTYPE == 'STORAGENODE' ]; then
    ssh -i /root/.ssh/so.key socore@$MSRV sudo /opt/so/saltstack/pillar/firewall/addfirewall.sh minions $MAINIP
    ssh -i /root/.ssh/so.key socore@$MSRV sudo /opt/so/saltstack/pillar/firewall/addfirewall.sh storage_nodes $MAINIP
    ssh -i /root/.ssh/so.key socore@$MSRV sudo /opt/so/saltstack/pillar/data/addtotab.sh nodestab $HOSTNAME $MAINIP $CPUCORES $RANDOMUID $MAININT $FSROOT $FSNSM
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
  if [ $INSTALLTYPE == 'STORAGENODE' ] || [ $INSTALLTYPE == 'EVALMODE' ]; then
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

  if ! grep -qE '^socore\ ALL=\(ALL\)\ NOPASSWD:(\/usr\/bin\/salt\-key|\/opt\/so\/saltstack)' /etc/sudoers; then
    # Update Sudoers so that socore can accept keys without a password
    echo "socore ALL=(ALL) NOPASSWD:/usr/bin/salt-key" | sudo tee -a /etc/sudoers
    echo "socore ALL=(ALL) NOPASSWD:/opt/so/saltstack/pillar/firewall/addfirewall.sh" | sudo tee -a /etc/sudoers
    echo "socore ALL=(ALL) NOPASSWD:/opt/so/saltstack/pillar/data/addtotab.sh" | sudo tee -a /etc/sudoers
  else
    echo "User socore already granted sudo privileges"
  fi

}

wazuh_repo_install() {

 if [ $OS == 'centos' ]; then
   # Add repo
   cat > /etc/yum.repos.d/wazuh.repo <<\EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/3.x/yum/
protect=1
EOF
 else
   # Get key
   curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
   # Add repo
   echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
 fi

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

whiptail_bro_version() {

  BROVERSION=$(whiptail --title "Security Onion Setup" --radiolist "What tool would you like to use to generate meta data?" 20 78 4 "ZEEK" "Install Zeek (aka Bro)"  ON \
  "COMMUNITY" "Install Community NSM" OFF "SURICATA" "SUPER EXPERIMENTAL" OFF 3>&1 1>&2 2>&3)

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

whiptail_cur_close_days() {

  CURCLOSEDAYS=$(whiptail --title "Security Onion Setup" --inputbox \
  "Please specify the threshold (in days) at which Elasticsearch indices will be closed" 10 60 $CURCLOSEDAYS 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_homenet_master() {

  # Ask for the HOME_NET on the master
  HNMASTER=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter your HOME_NET separated by ," 10 60 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

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
  "Choose Install Type:" 20 78 14 \
  "SENSORONLY" "Create a forward only sensor" ON \
  "STORAGENODE" "Add a Storage Hot Node with parsing" OFF \
  "MASTERONLY" "Start a new grid" OFF \
  "PARSINGNODE" "TODO Add a dedicated Parsing Node" OFF \
  "HOTNODE" "TODO Add a Hot Node (Storage Node without Parsing)" OFF \
  "WARMNODE" "TODO Add a Warm Node to an existing Hot or Storage node" OFF \
  "EVALMODE" "Evaluate all the things" OFF \
  "WAZUH" "TODO Stand Alone Wazuh Node" OFF \
  "STRELKA" "TODO Stand Alone Strelka Node" OFF \
  "FLEET" "TODO Stand Alone Fleet OSQuery Node" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_log_size_limit() {

   LOG_SIZE_LIMIT=$(whiptail --title "Security Onion Setup" --inputbox \
  "Please specify the amount of disk space (in GB) you would like to allocate for Elasticsearch data storage. \
  By default, this is set to 85% of the disk space allotted for /nsm." 10 60 $LOG_SIZE_LIMIT 3>&1 1>&2 2>&3)

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
  "Suricata" "Suricata 4.X" ON  \
  "Snort" "Snort 3.0 Beta" OFF 3>&1 1>&2 2>&3 )

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
  "Enter your Master Server HOSTNAME. It is CASE SENSITIVE!" 10 60 XXXX 3>&1 1>&2 2>&3)

  # See if it resolves. Otherwise prompt to add to host file
  TESTHOST=$(host $MSRV)

  if [[ $TESTHOST = *"not found"* ]]; then
    add_master_hostfile
  fi


  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

# Ask if you want to do advanced setup of the Master
whiptail_master_adv() {
  MASTERADV=$(whiptail --title "Security Onion Setup" --radiolist \
  "Choose what type of master install:" 20 78 4 \
  "BASIC" "Install master with recommended settings" ON  \
  "ADVANCED" "Do additional configuration to the master" OFF 3>&1 1>&2 2>&3 )
}

# Ask which additional components to install
whiptail_master_adv_service_brologs() {

  BLOGS=$(whiptail --title "Security Onion Setup" --checklist "Please Select Logs to Send:" 24 78 12 \
  "conn" "Connection Logging" ON \
  "dce_rpc" "RPC Logs" ON \
  "dhcp" "DHCP Logs" ON \
  "dhcpv6" "DHCP IPv6 Logs" ON \
  "dnp3" "DNP3 Logs" ON \
  "dns" "DNS Logs" ON \
  "dpd" "DPD Logs" ON \
  "files" "Files Logs" ON \
  "ftp" "FTP Logs" ON \
  "http" "HTTP Logs" ON \
  "intel" "Intel Hits Logs" ON \
  "irc" "IRC Chat Logs" ON \
  "kerberos" "Kerberos Logs" ON \
  "modbus" "MODBUS Logs" ON \
  "mqtt" "MQTT Logs" ON \
  "notice" "Zeek Notice Logs" ON \
  "ntlm" "NTLM Logs" ON \
  "openvpn" "OPENVPN Logs" ON \
  "pe" "PE Logs" ON \
  "radius" "Radius Logs" ON \
  "rfb" "RFB Logs" ON \
  "rdp" "RDP Logs" ON \
  "signatures" "Signatures Logs" ON \
  "sip" "SIP Logs" ON \
  "smb_files" "SMB Files Logs" ON \
  "smb_mapping" "SMB Mapping Logs" ON \
  "smtp" "SMTP Logs" ON \
  "snmp" "SNMP Logs" ON \
  "software" "Software Logs" ON \
  "ssh" "SSH Logs" ON \
  "ssl" "SSL Logs" ON \
  "syslog" "Syslog Logs" ON \
  "telnet" "Telnet Logs" ON \
  "tunnel" "Tunnel Logs" ON \
  "weird" "Zeek Weird Logs" ON \
  "mysql" "MySQL Logs" ON \
  "socks" "SOCKS Logs" ON \
  "x509" "x.509 Logs" ON 3>&1 1>&2 2>&3 )
}

whiptail_master_adv_service_grafana() {
  echo "blah"
}

whiptail_master_adv_service_osquery() {
  #MOSQ=$()
  echo "blah"

}

whiptail_master_adv_service_wazuh() {
  echo "blah"
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

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_es_heap() {

  es_heapsize
  NODE_ES_HEAP_SIZE=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter ES Heap Size: \n \n(Recommended value is pre-populated)" 10 60 $ES_HEAP_SIZE 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_ls_heap() {

  ls_heapsize
  NODE_LS_HEAP_SIZE=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter LogStash Heap Size: \n \n(Recommended value is pre-populated)" 10 60 $LS_HEAP_SIZE 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_ls_pipeline_worker() {

  LSPIPELINEWORKERS=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter LogStash Pipeline Workers: \n \n(Recommended value is pre-populated)" 10 60 $CPUCORES 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_ls_pipline_batchsize() {

  LSPIPELINEBATCH=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter LogStash Pipeline Batch Size: \n \n(Default value is pre-populated)" 10 60 125 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_ls_input_threads() {

  LSINPUTTHREADS=$(whiptail --title "Security Onion Setup" --inputbox \
    "\nEnter LogStash Input Threads: \n \n(Default value is pre-populated)" 10 60 1 3>&1 1>&2 2>&3)

    local exitstatus=$?
    whiptail_check_exitstatus $exitstatus

}

whiptail_node_ls_input_batch_count() {

  LSINPUTBATCHCOUNT=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter LogStash Input Batch Count: \n \n(Default value is pre-populated)" 10 60 125 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

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

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

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

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_updates() {

  NODEUPDATES=$(whiptail --title "Security Onion Setup" --radiolist \
  "How would you like to download updates for this node?:" 20 78 4 \
  "MASTER" "Download OS/Docker updates from the Master." ON \
  "OPEN" "Download updates directly from the Internet" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

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

  # Create a temp dir to get started
  install_prep

  # Let folks know they need their management interface already set up.
  whiptail_network_notice

  # Go ahead and gen the keys so we can use them for any sensor type - Disabled for now
  #minio_generate_keys

  # What kind of install are we doing?
  whiptail_install_type

  ####################
  ##     Master     ##
  ####################

  if [ $INSTALLTYPE == 'MASTERONLY' ]; then

    # Would you like to do an advanced install?
    whiptail_master_adv

    # Pick the Management NIC
    whiptail_management_nic

    # Choose Zeek or Community NSM
    whiptail_bro_version

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

    # Do Advacned Setup if they chose it
    if [ $MASTERADV == 'ADVANCED' ]; then
      # Ask which bro logs to enable - Need to add Suricata check
      if [ $BROVERSION != 'SURICATA' ]; then
        whiptail_master_adv_service_brologs
      fi
      whiptail_master_adv_service_osquery
      whiptail_master_adv_service_grafana
      whiptail_master_adv_service_wazuh
    fi

    # Last Chance to back out
    whiptail_make_changes
    generate_passwords
    auth_pillar
    clear_master
    mkdir -p /nsm
    get_filesystem_root
    get_filesystem_nsm
    # Enable Bro Logs
    bro_logs_enabled

    # Figure out the main IP address
    get_main_ip

    # Add the user so we can sit back and relax
    echo ""
    echo "**** Please set a password for socore. You will use this password when setting up other Nodes/Sensors"
    echo ""
    add_socore_user_master

    #echo "** Adding Wazuh users **"
    #add_wazuh_users

    echo "** Installing Wazuh repo **"
    wazuh_repo_install

    # Install salt and dependencies
    echo " ** Installing Salt and Dependencies **"
    saltify >>~/sosetup.log 2>&1
    docker_install

    # Configure the Minion
    echo " ** Configuring Minion **"
    configure_minion master >>~/sosetup.log 2>&1

    # Install the salt master
    echo " ** Installing Salt Master **"
    install_master >>~/sosetup.log 2>&1

    # Copy the data over
    salt_master_directories >>~/sosetup.log 2>&1

    # Update sudoers file to allow keys and firewalls to be changed
    update_sudoers

    # Change perms on the master dir
    chown_salt_master

    # Determine the ES Heap Size
    es_heapsize

    # Determine the Logstash Heap Size
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

    # Open the firewall
    echo "** Setting the initial firewall policy **"
    set_initial_firewall_policy

    # Do the big checkin but first let them know it will take a bit.
    salt_checkin_message
    salt_checkin

    # Enable salt to run a checking when the service starts
    checkin_at_boot

    # We are done!
    whiptail_setup_complete

  fi

  ####################
  ##     Sensor     ##
  ####################

  if [ $INSTALLTYPE == 'SENSORONLY' ]; then
    whiptail_management_nic
    filter_nics
    whiptail_bond_nics
    whiptail_management_server
    whiptail_master_updates
    set_updates
    whiptail_homenet_sensor
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
    clear_master
    mkdir -p /nsm
    get_filesystem_root
    get_filesystem_nsm
    #add_wazuh_users
    wazuh_repo_install
    copy_ssh_key
    set_initial_firewall_policy
    create_bond
    sensor_pillar
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
    checkin_at_boot

    whiptail_setup_complete

  fi

  #######################
  ##     Eval Mode     ##
  #######################

  if [ $INSTALLTYPE == 'EVALMODE' ]; then
    # Select the management NIC
    whiptail_management_nic

    # Filter out the management NIC
    filter_nics

    # Select which NICs are in the bond
    whiptail_bond_nics

    # Snag the HOME_NET
    whiptail_homenet_master

    # Set a bunch of stuff since this is eval
    es_heapsize
    ls_heapsize
    NODE_ES_HEAP_SIZE=$ES_HEAP_SIZE
    NODE_LS_HEAP_SIZE=$LS_HEAP_SIZE
    LSPIPELINEWORKERS=1
    LSPIPELINEBATCH=125
    LSINPUTTHREADS=1
    LSINPUTBATCHCOUNT=125
    RULESETUP=ETOPEN
    NSMSETUP=BASIC
    NIDS=Suricata
    BROVERSION=ZEEK
    CURCLOSEDAYS=30
    whiptail_make_changes
    generate_passwords
    clear_master
    mkdir -p /nsm
    get_filesystem_root
    get_filesystem_nsm
    get_log_size_limit
    get_main_ip
    # Add the user so we can sit back and relax
    echo ""
    echo "**** Please set a password for socore. You will use this password when setting up other Nodes/Sensors"
    echo ""
    add_socore_user_master
    #add_wazuh_users
    wazuh_repo_install
    create_bond
    saltify
    docker_install
    install_master
    # Copy the data over
    salt_master_directories
    update_sudoers
    # Change perms on the master dir
    chown_salt_master
    # Set the static values
    master_static
    echo "** Generating the master pillar **"
    master_pillar
    configure_minion eval
    set_node_type
    node_pillar
    set_initial_firewall_policy
    salt_firstcheckin
    accept_salt_key_local
    salt_checkin_message
    salt_checkin
    checkin_at_boot
    whiptail_setup_complete
  fi

  ###################
  ##     Nodes     ##
  ###################

  if [ $INSTALLTYPE == 'STORAGENODE' ] || [ $INSTALLTYPE == 'PARSINGNODE' ] || [ $INSTALLTYPE == 'HOTNODE' ] || [ $INSTALLTYPE == 'WARMNODE' ]; then
    whiptail_management_nic
    whiptail_management_server
    whiptail_master_updates
    set_updates
    get_log_size_limit
    whiptail_log_size_limit
    CURCLOSEDAYS=30
    whiptail_cur_close_days
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
      LSPIPELINEWORKERS=$CPUCORES
      LSPIPELINEBATCH=125
      LSINPUTTHREADS=1
      LSINPUTBATCHCOUNT=125
    fi
    whiptail_make_changes
    clear_master
    mkdir -p /nsm
    get_filesystem_root
    get_filesystem_nsm
    #add_wazuh_users
    wazuh_repo_install
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
    checkin_at_boot

    whiptail_setup_complete
  fi

else
    exit
fi
