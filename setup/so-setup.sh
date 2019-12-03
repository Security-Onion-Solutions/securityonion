#!/bin/bash

# Copyright 2014,2015,2016,2017,2018,2019 Security Onion Solutions, LLC

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

# Source the other pieces of the setup
source functions.sh
source whiptail.sh

# See if this is an ISO install
OPTIONS=$1

if [[ $OPTIONS = 'iso' ]]; then
  ISOINSTALL=1
else
  ISOINSTALL=0
fi

# Global Variables
HOSTNAME=$(cat /etc/hostname)
MINION_ID=$(echo $HOSTNAME | awk -F. {'print $1'})
TOTAL_MEM=`grep MemTotal /proc/meminfo | awk '{print $2}' | sed -r 's/.{3}$//'`
NICS=$(ip link | awk -F: '$0 !~ "lo|vir|veth|br|docker|wl|^[^0-9]"{print $2 " \"" "Interface" "\"" " OFF"}')
CPUCORES=$(cat /proc/cpuinfo | grep processor | wc -l)
LISTCORES=$(cat /proc/cpuinfo | grep processor | awk '{print $3 " \"" "core" "\""}')
RANDOMUID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
NODE_ES_PORT="9200"
SETUPLOG="/root/sosetup.log"
# End Global Variables

# Reset the Install Log
date -u >$SETUPLOG 2>&1

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

  # Set the hostname to reduce errors
  whiptail_set_hostname

  # Go ahead and gen the keys so we can use them for any sensor type - Disabled for now
  #minio_generate_keys

  # What kind of install are we doing?
  whiptail_install_type

  # How do we want to handle OS patching? manual, auto or scheduled days and hours
  whiptail_patch_schedule
  case $PATCHSCHEDULE in
    'New Schedule')
      whiptail_patch_schedule_select_days
      whiptail_patch_schedule_select_hours
      whiptail_patch_name_new_schedule
      patch_schedule_os_new
      ;;
    'Import Schedule')
      whiptail_patch_schedule_import
      ;;
    Automatic)
      PATCHSCHEDULENAME=auto
      ;;
    Manual)
      PATCHSCHEDULENAME=manual
      ;;
  esac

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
    whiptail_enable_components
    process_components

    # Do Advacned Setup if they chose it
    if [ $MASTERADV == 'ADVANCED' ]; then
      # Ask which bro logs to enable - Need to add Suricata check
      if [ $BROVERSION != 'SURICATA' ]; then
        whiptail_master_adv_service_brologs
      fi
    fi

    whiptail_create_socore_user
    SCMATCH=no
    while [ $SCMATCH != yes ]; do
      whiptail_create_socore_user_password1
      whiptail_create_socore_user_password2
      check_socore_pass
    done

    # Last Chance to back out
    whiptail_make_changes
    set_hostname
    generate_passwords
    auth_pillar
    clear_master
    mkdir -p /nsm
    get_filesystem_root
    get_filesystem_nsm
    # Enable Bro Logs
    # comment this out since we already copy this file to the destination that this function writes to
    #bro_logs_enabled

    # Figure out the main IP address
    get_main_ip

    # Add the user so we can sit back and relax
    #echo ""
    #echo "**** Please set a password for socore. You will use this password when setting up other Nodes/Sensors"
    #echo ""
    add_socore_user_master

    # Install salt and dependencies
    {
      sleep 0.5
      install_python3 >> $SETUPLOG 2>&1
      echo -e "XXX\n1\nInstalling and configuring Salt... \nXXX"
      echo " ** Installing Salt and Dependencies **" >> $SETUPLOG
      saltify >> $SETUPLOG 2>&1
      echo -e "XXX\n5\nInstalling Docker... \nXXX"
      docker_install >> $SETUPLOG 2>&1
      echo -e "XXX\n10\nConfiguring Salt Master... \nXXX"
      echo " ** Configuring Minion **" >> $SETUPLOG
      configure_minion master >> $SETUPLOG 2>&1
      echo " ** Installing Salt Master **" >> $SETUPLOG
      install_master >> $SETUPLOG 2>&1
      salt_install_mysql_deps >> $SETUPLOG 2>&1
      salt_master_directories >> $SETUPLOG 2>&1
      update_sudoers >> $SETUPLOG 2>&1
      chown_salt_master >> $SETUPLOG 2>&1
      es_heapsize >> $SETUPLOG 2>&1
      ls_heapsize >> $SETUPLOG 2>&1
      echo -e "XXX\n25\nConfiguring Default Pillars... \nXXX"
      master_static >> $SETUPLOG 2>&1
      echo "** Generating the master pillar **" >> $SETUPLOG
      master_pillar >> $SETUPLOG 2>&1
      echo "** Generating the patch pillar **" >> $SETUPLOG
      patch_pillar >> $SETUPLOG 2>&1
      echo -e "XXX\n30\nAccepting Salt Keys... \nXXX"
      echo -e "XXX\n24\nCopying Minion Pillars to Master... \nXXX"
      copy_minion_tmp_files >> $SETUPLOG 2>&1
      # Do a checkin to push the key up
      echo "** Pushing the key up to Master **" >> $SETUPLOG
      salt_firstcheckin >> $SETUPLOG 2>&1
      # Accept the Master Key
      echo "** Accepting the key on the master **" >> $SETUPLOG
      accept_salt_key_local >> $SETUPLOG 2>&1
      echo -e "XXX\n35\nConfiguring Firewall... \nXXX"
      # Open the firewall
      echo "** Setting the initial firewall policy **" >> $SETUPLOG
      set_initial_firewall_policy >> $SETUPLOG 2>&1
      # Do the big checkin but first let them know it will take a bit.
      echo -e "XXX\n40\nGenerating CA... \nXXX"
      salt_checkin >> $SETUPLOG 2>&1
      salt-call state.apply ca >> $SETUPLOG 2>&1
      salt-call state.apply ssl >> $SETUPLOG 2>&1
      echo -e "XXX\n43\nInstalling Common Components... \nXXX"
      salt-call state.apply common >> $SETUPLOG 2>&1
      echo -e "XXX\n45\nApplying firewall rules... \nXXX"
      salt-call state.apply firewall >> $SETUPLOG 2>&1
      salt-call state.apply master >> $SETUPLOG 2>&1
      salt-call state.apply idstools >> $SETUPLOG 2>&1
      echo -e "XXX\n40\nInstalling Redis... \nXXX"
      salt-call state.apply redis >> $SETUPLOG 2>&1
      if [[ $OSQUERY == '1' ]]; then
        echo -e "XXX\n41\nInstalling MySQL... \nXXX"
        salt-call state.apply mysql >> $SETUPLOG 2>&1
      fi
      echo -e "XXX\n45\nInstalling Elastic Components... \nXXX"
      salt-call state.apply elasticsearch >> $SETUPLOG 2>&1
      salt-call state.apply logstash >> $SETUPLOG 2>&1
      salt-call state.apply kibana >> $SETUPLOG 2>&1
      salt-call state.apply elastalert >> $SETUPLOG 2>&1
      if [[ $WAZUH == '1' ]]; then
        echo -e "XXX\n68\nInstalling Wazuh... \nXXX"
        salt-call state.apply wazuh >> $SETUPLOG 2>&1
      fi
      echo -e "XXX\n75\nInstalling Filebeat... \nXXX"
      salt-call state.apply filebeat >> $SETUPLOG 2>&1
      salt-call state.apply utility >> $SETUPLOG 2>&1
      salt-call state.apply schedule >> $SETUPLOG 2>&1
      if [[ $OSQUERY == '1' ]]; then
        echo -e "XXX\n79\nInstalling Fleet... \nXXX"
        salt-call state.apply fleet >> $SETUPLOG 2>&1
        salt-call state.apply launcher >> $SETUPLOG 2>&1
      fi
      echo -e "XXX\n85\nConfiguring SOctopus... \nXXX"
      salt-call state.apply soctopus >> $SETUPLOG 2>&1
      if [[ $THEHIVE == '1' ]]; then
        echo -e "XXX\n87\nInstalling TheHive... \nXXX"
        salt-call state.apply hive >> $SETUPLOG 2>&1
      fi
      if [[ $PLAYBOOK == '1' ]]; then
        echo -e "XXX\n89\nInstalling Playbook... \nXXX"
        salt-call state.apply playbook >> $SETUPLOG 2>&1
      fi
      echo -e "XXX\n75\nEnabling Checking at Boot... \nXXX"
      checkin_at_boot >> $SETUPLOG 2>&1
      echo -e "XX\n97\nFinishing touches... \nXXX"
      filter_unused_nics >> $SETUPLOG 2>&1
      network_setup >> $SETUPLOG 2>&1
      echo -e "XXX\n98\nVerifying Setup... \nXXX"
      salt-call state.highstate >> $SETUPLOG 2>&1
    } |whiptail --title "Hybrid Hunter Install" --gauge "Please wait while installing" 6 60 0
    GOODSETUP=$(tail -10 $SETUPLOG | grep Failed | awk '{ print $2}')
    if [[ $GOODSETUP == '0' ]]; then
      whiptail_setup_complete
      if [[ $THEHIVE == '1' ]]; then
        check_hive_init_then_reboot
      else
        shutdown -r now
      fi
    else
      whiptail_setup_failed
      shutdown -r now
    fi

  fi

  ####################
  ##     Sensor     ##
  ####################

  if [ $INSTALLTYPE == 'SENSORONLY' ]; then
    whiptail_management_nic
    filter_unused_nics
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
    set_hostname
    clear_master
    mkdir -p /nsm
    get_filesystem_root
    get_filesystem_nsm
    copy_ssh_key >> $SETUPLOG 2>&1
    {
      sleep 0.5
      echo -e "XXX\n0\nSetting Initial Firewall Policy... \nXXX"
      set_initial_firewall_policy >> $SETUPLOG 2>&1
      echo -e "XXX\n1\nInstalling pip3... \nXXX"
      install_python3 >> $SETUPLOG 2>&1
      echo -e "XXX\n3\nCreating Bond Interface... \nXXX"
      create_sensor_bond >> $SETUPLOG 2>&1
      echo -e "XXX\n4\nGenerating Sensor Pillar... \nXXX"
      sensor_pillar >> $SETUPLOG 2>&1
      echo "** Generating the patch pillar **" >> $SETUPLOG
      patch_pillar >> $SETUPLOG 2>&1
      echo -e "XXX\n5\nInstalling Salt Components... \nXXX"
      saltify >> $SETUPLOG 2>&1
      echo -e "XXX\n20\nInstalling Docker... \nXXX"
      docker_install >> $SETUPLOG 2>&1
      echo -e "XXX\n22\nConfiguring Salt Minion... \nXXX"
      configure_minion sensor >> $SETUPLOG 2>&1
      echo -e "XXX\n24\nCopying Minion Pillars to Master... \nXXX"
      copy_minion_tmp_files >> $SETUPLOG 2>&1
      echo -e "XXX\n25\nSending Salt Key to Master... \nXXX"
      salt_firstcheckin >> $SETUPLOG 2>&1
      echo -e "XXX\n26\nTelling the Master to Accept Key... \nXXX"
      # Accept the Salt Key
      accept_salt_key_remote >> $SETUPLOG 2>&1
      echo -e "XXX\n27\nApplying SSL Certificates... \nXXX"
      salt-call state.apply ca >> $SETUPLOG 2>&1
      salt-call state.apply ssl >> $SETUPLOG 2>&1
      echo -e "XXX\n35\nInstalling Core Components... \nXXX"
      salt-call state.apply common >> $SETUPLOG 2>&1
      salt-call state.apply firewall >> $SETUPLOG 2>&1
      echo -e "XXX\n50\nInstalling PCAP... \nXXX"
      salt-call state.apply pcap >> $SETUPLOG 2>&1
      echo -e "XXX\n60\nInstalling IDS components... \nXXX"
      salt-call state.apply suricata >> $SETUPLOG 2>&1
      checkin_at_boot >> $SETUPLOG 2>&1
      echo -e "XX\n97\nFinishing touches... \nXXX"
      filter_unused_nics >> $SETUPLOG 2>&1
      network_setup >> $SETUPLOG 2>&1
      echo -e "XXX\n98\nVerifying Setup... \nXXX"
      salt-call state.highstate >> $SETUPLOG 2>&1
    } |whiptail --title "Hybrid Hunter Install" --gauge "Please wait while installing" 6 60 0
    GOODSETUP=$(tail -10 $SETUPLOG | grep Failed | awk '{ print $2}')
    if [[ $GOODSETUP == '0' ]]; then
      whiptail_setup_complete
      shutdown -r now
    else
      whiptail_setup_failed
      shutdown -r now
    fi
  fi

  #######################
  ##     Eval Mode     ##
  #######################

  if [ $INSTALLTYPE == 'EVALMODE' ]; then
    # Select the management NIC
    whiptail_management_nic

    # Filter out the management NIC
    filter_unused_nics

    # Select which NICs are in the bond
    whiptail_bond_nics

    # Snag the HOME_NET
    whiptail_homenet_master
    whiptail_eval_adv_warning
    whiptail_enable_components

    # Set a bunch of stuff since this is eval
    es_heapsize
    ls_heapsize
    NODE_ES_HEAP_SIZE="600m"
    NODE_LS_HEAP_SIZE="500m"
    LSPIPELINEWORKERS=1
    LSPIPELINEBATCH=125
    LSINPUTTHREADS=1
    LSINPUTBATCHCOUNT=125
    RULESETUP=ETOPEN
    NSMSETUP=BASIC
    NIDS=Suricata
    BROVERSION=ZEEK
    CURCLOSEDAYS=30
    process_components
    whiptail_create_socore_user
    SCMATCH=no
    while [ $SCMATCH != yes ]; do
      whiptail_create_socore_user_password1
      whiptail_create_socore_user_password2
      check_socore_pass
    done
    whiptail_make_changes
    set_hostname
    generate_passwords
    auth_pillar
    clear_master
    mkdir -p /nsm
    get_filesystem_root
    get_filesystem_nsm
    get_log_size_limit
    get_main_ip
    # Add the user so we can sit back and relax
    add_socore_user_master
    {
      sleep 0.5
      echo -e "XXX\n0\nCreating Bond Interface... \nXXX"
      create_sensor_bond >> $SETUPLOG 2>&1
      echo -e "XXX\n1\nInstalling Python 3... \nXXX"
      install_python3 >> $SETUPLOG 2>&1
      echo -e "XXX\n2\nInstalling saltstack... \nXXX"
      saltify >> $SETUPLOG 2>&1
      echo -e "XXX\n3\nInstalling docker... \nXXX"
      docker_install >> $SETUPLOG 2>&1
      echo -e "XXX\n5\nInstalling master code... \nXXX"
      install_master >> $SETUPLOG 2>&1
      echo -e "XXX\n5\nInstalling mysql dependencies for saltstack... \nXXX"
      salt_install_mysql_deps >> $SETUPLOG 2>&1
      echo -e "XXX\n6\nCopying salt code... \nXXX"
      salt_master_directories >> $SETUPLOG 2>&1
      echo -e "XXX\n6\nupdating suduers... \nXXX"
      update_sudoers >> $SETUPLOG 2>&1
      echo -e "XXX\n7\nFixing some permissions... \nXXX"
      chown_salt_master >> $SETUPLOG 2>&1
      echo -e "XXX\n7\nCreating the static pillar... \nXXX"
      # Set the static values
      master_static >> $SETUPLOG 2>&1
      echo -e "XXX\n7\nCreating the master pillar... \nXXX"
      master_pillar >> $SETUPLOG 2>&1
      echo "** Generating the patch pillar **" >> $SETUPLOG
      patch_pillar >> $SETUPLOG 2>&1
      echo -e "XXX\n7\nConfiguring minion... \nXXX"
      configure_minion eval >> $SETUPLOG 2>&1
      echo -e "XXX\n7\nSetting the node type to eval... \nXXX"
      set_node_type >> $SETUPLOG 2>&1
      echo -e "XXX\n7\nStorage node pillar... \nXXX"
      node_pillar >> $SETUPLOG 2>&1
      echo -e "XXX\n8\nCreating firewall policies... \nXXX"
      set_initial_firewall_policy >> $SETUPLOG 2>&1
      echo -e "XXX\n24\nCopying Minion Pillars to Master... \nXXX"
      copy_minion_tmp_files >> $SETUPLOG 2>&1
      echo -e "XXX\n10\nRegistering agent... \nXXX"
      salt_firstcheckin >> $SETUPLOG 2>&1
      echo -e "XXX\n11\nAccepting Agent... \nXXX"
      accept_salt_key_local >> $SETUPLOG 2>&1
      echo -e "XXX\n12\nRunning the SSL states... \nXXX"
      salt_checkin >> $SETUPLOG 2>&1
      salt-call state.apply ca >> $SETUPLOG 2>&1
      salt-call state.apply ssl >> $SETUPLOG 2>&1
      echo -e "XXX\n15\nInstalling core components... \nXXX"
      salt-call state.apply common >> $SETUPLOG 2>&1
      echo -e "XXX\n18\nInitializing firewall rules... \nXXX"
      salt-call state.apply firewall >> $SETUPLOG 2>&1
      echo -e "XXX\n25\nInstalling master components... \nXXX"
      salt-call state.apply master >> $SETUPLOG 2>&1
      salt-call state.apply idstools >> $SETUPLOG 2>&1
      if [[ $OSQUERY == '1' ]]; then
        salt-call state.apply mysql >> $SETUPLOG 2>&1
      fi
      echo -e "XXX\n35\nInstalling ElasticSearch... \nXXX"
      salt-call state.apply elasticsearch >> $SETUPLOG 2>&1
      echo -e "XXX\n40\nInstalling Logstash... \nXXX"
      salt-call state.apply logstash >> $SETUPLOG 2>&1
      echo -e "XXX\n45\nInstalling Kibana... \nXXX"
      salt-call state.apply kibana >> $SETUPLOG 2>&1
      echo -e "XXX\n50\nInstalling pcap... \nXXX"
      salt-call state.apply pcap >> $SETUPLOG 2>&1
      echo -e "XXX\n52\nInstalling Suricata... \nXXX"
      salt-call state.apply suricata >> $SETUPLOG 2>&1
      echo -e "XXX\n54\nInstalling Zeek... \nXXX"
      salt-call state.apply bro >> $SETUPLOG 2>&1
      echo -e "XXX\n56\nInstalling curator... \nXXX"
      salt-call state.apply curator >> $SETUPLOG 2>&1
      echo -e "XXX\n58\nInstalling elastalert... \nXXX"
      salt-call state.apply elastalert >> $SETUPLOG 2>&1
      if [[ $OSQUERY == '1' ]]; then
        echo -e "XXX\n60\nInstalling fleet... \nXXX"
        salt-call state.apply fleet >> $SETUPLOG 2>&1
        salt-call state.apply redis >> $SETUPLOG 2>&1
      fi
      if [[ $WAZUH == '1' ]]; then
        echo -e "XXX\n65\nInstalling Wazuh components... \nXXX"
        salt-call state.apply wazuh >> $SETUPLOG 2>&1
      fi
      echo -e "XXX\n85\nInstalling filebeat... \nXXX"
      salt-call state.apply filebeat >> $SETUPLOG 2>&1
      salt-call state.apply utility >> $SETUPLOG 2>&1
      echo -e "XXX\n90\nInstalling misc components... \nXXX"
      salt-call state.apply schedule >> $SETUPLOG 2>&1
      salt-call state.apply soctopus >> $SETUPLOG 2>&1
      if [[ $THEHIVE == '1' ]]; then
        echo -e "XXX\n91\nInstalling The Hive... \nXXX"
        salt-call state.apply hive >> $SETUPLOG 2>&1
      fi
      if [[ $PLAYBOOK == '1' ]]; then
        echo -e "XXX\n93\nInstalling Playbook... \nXXX"
        salt-call state.apply playbook >> $SETUPLOG 2>&1
      fi
      echo -e "XXX\n95\nSetting checkin to run on boot... \nXXX"
      checkin_at_boot >> $SETUPLOG 2>&1
      echo -e "XX\n97\nFinishing touches... \nXXX"
      filter_unused_nics >> $SETUPLOG 2>&1
      network_setup >> $SETUPLOG 2>&1
      echo -e "XXX\n98\nVerifying Setup... \nXXX"
      salt-call state.highstate >> $SETUPLOG 2>&1
    } |whiptail --title "Hybrid Hunter Install" --gauge "Please wait while installing" 6 60 0
    GOODSETUP=$(tail -10 $SETUPLOG | grep Failed | awk '{ print $2}')
    if [ $OS == 'centos' ]; then
      if [[ $GOODSETUP == '1' ]]; then
        whiptail_setup_complete
        if [[ $THEHIVE == '1' ]]; then
          check_hive_init_then_reboot
        else
          shutdown -r now
        fi
      else
        whiptail_setup_failed
        shutdown -r now
      fi
    else
      if [[ $GOODSETUP == '0' ]]; then
        whiptail_setup_complete
        if [[ $THEHIVE == '1' ]]; then
          check_hive_init_then_reboot
        else
          shutdown -r now
        fi
      else
        whiptail_setup_failed
        shutdown -r now
      fi
    fi
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
    CURCLOSEDAYS=30
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
      whiptail_cur_close_days
      whiptail_log_size_limit
    else
      NODE_ES_HEAP_SIZE=$ES_HEAP_SIZE
      NODE_LS_HEAP_SIZE=$LS_HEAP_SIZE
      LSPIPELINEWORKERS=$CPUCORES
      LSPIPELINEBATCH=125
      LSINPUTTHREADS=1
      LSINPUTBATCHCOUNT=125
    fi
    whiptail_make_changes
    set_hostname
    clear_master
    mkdir -p /nsm
    get_filesystem_root
    get_filesystem_nsm
    copy_ssh_key >> $SETUPLOG 2>&1
    {
      sleep 0.5
      echo -e "XXX\n0\nSetting Initial Firewall Policy... \nXXX"
      set_initial_firewall_policy >> $SETUPLOG 2>&1
      echo -e "XXX\n1\nInstalling pip3... \nXXX"
      install_python3 >> $SETUPLOG 2>&1
      echo -e "XXX\n5\nInstalling Salt Packages... \nXXX"
      saltify >> $SETUPLOG 2>&1
      echo -e "XXX\n20\nInstalling Docker... \nXXX"
      docker_install >> $SETUPLOG 2>&1
      echo -e "XXX\n30\nInitializing Minion... \nXXX"
      configure_minion node >> $SETUPLOG 2>&1
      set_node_type >> $SETUPLOG 2>&1
      node_pillar >> $SETUPLOG 2>&1
      echo "** Generating the patch pillar **" >> $SETUPLOG
      patch_pillar >> $SETUPLOG 2>&1
      echo -e "XXX\n24\nCopying Minion Pillars to Master... \nXXX"
      copy_minion_tmp_files >> $SETUPLOG 2>&1
      echo -e "XXX\n35\nSending and Accepting Salt Key... \nXXX"
      salt_firstcheckin >> $SETUPLOG 2>&1
      # Accept the Salt Key
      accept_salt_key_remote >> $SETUPLOG 2>&1
      echo -e "XXX\n40\nApplying SSL Certificates... \nXXX"
      salt-call state.apply ca >> $SETUPLOG 2>&1
      salt-call state.apply ssl >> $SETUPLOG 2>&1
      echo -e "XXX\n50\nConfiguring Firewall... \nXXX"
      salt-call state.apply common >> $SETUPLOG 2>&1
      salt-call state.apply firewall >> $SETUPLOG 2>&1
      echo -e "XXX\n70\nInstalling Elastic Components... \nXXX"
      salt-call state.apply logstash >> $SETUPLOG 2>&1
      salt-call state.apply elasticsearch >> $SETUPLOG 2>&1
      salt-call state.apply curator >> $SETUPLOG 2>&1
      salt-call state.apply filebeat >> $SETUPLOG 2>&1
      checkin_at_boot >> $SETUPLOG 2>&1
      echo -e "XX\n97\nFinishing touches... \nXXX"
      filter_unused_nics >> $SETUPLOG 2>&1
      network_setup >> $SETUPLOG 2>&1
      echo -e "XXX\n98\nVerifying Setup... \nXXX"
    } |whiptail --title "Hybrid Hunter Install" --gauge "Please wait while installing" 6 60 0
    GOODSETUP=$(tail -10 $SETUPLOG | grep Failed | awk '{ print $2}')
    if [[ $GOODSETUP == '0' ]]; then
      whiptail_setup_complete
      shutdown -r now
    else
      whiptail_setup_failed
      shutdown -r now
    fi

    #set_initial_firewall_policy
    #saltify
    #docker_install
    #configure_minion node
    #set_node_type
    #node_pillar
    #copy_minion_pillar nodes
    #salt_checkin
    # Accept the Salt Key
    #accept_salt_key_remote
    # Do the big checkin but first let them know it will take a bit.
    #salt_checkin_message
    #salt_checkin
    #checkin_at_boot

    #whiptail_setup_complete
  fi

else
    exit
fi
