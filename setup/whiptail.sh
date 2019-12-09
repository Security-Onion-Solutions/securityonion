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

whiptail_basic_bro() {

  BASICBRO=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter the number of bro processes:" 10 75 $LBPROCS 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_basic_suri() {

  BASICSURI=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter the number of Suricata Processes:" 10 75 $LBPROCS 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_bro_pins() {

  BROPINS=$(whiptail --noitem --title "Pin Bro CPUS" --checklist "Please Select $LBPROCS cores to pin Bro to:" 20 75 12 ${LISTCORES[@]} 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_bro_version() {

  BROVERSION=$(whiptail --title "Security Onion Setup" --radiolist "What tool would you like to use to generate meta data?" 20 75 4 "ZEEK" "Install Zeek (aka Bro)"  ON \
  "COMMUNITY" "Install Community NSM" OFF "SURICATA" "SUPER EXPERIMENTAL" OFF 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_bond_nics() {

  local nic_list=()
  for FNIC in ${FNICS[@]}; do
    nic_list+=($FNIC "Interface" "OFF")
  done

  BNICS=$(whiptail --title "NIC Setup" --checklist "Please add NICs to the Monitor Interface" 20 75 12 ${nic_list[@]} 3>&1 1>&2 2>&3 )
  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

  while [ -z "$BNICS" ]
  do
    BNICS=$(whiptail --title "NIC Setup" --checklist "Please add NICs to the Monitor Interface" 20 75 12 ${nic_list[@]} 3>&1 1>&2 2>&3 )
    local exitstatus=$?
    whiptail_check_exitstatus $exitstatus
  done

}

whiptail_bond_nics_mtu() {

  # Set the MTU on the monitor interface
  MTU=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter the MTU for the monitor NICs" 10 75 1500 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_cancel() {

  whiptail --title "Security Onion Setup" --msgbox "Cancelling Setup. No changes have been made." 8 75
  if [ -d "/root/installtmp" ]; then
    echo "/root/installtmp exists" >> $SETUPLOG 2>&1
    install_cleanup
    echo "/root/installtmp removed" >> $SETUPLOG 2>&1
  fi
  exit

}

whiptail_check_exitstatus() {

  if [ $1 == '1' ]; then
    echo "They hit cancel"
    whiptail_cancel
  fi

}

whiptail_create_socore_user() {

  whiptail --title "Security Onion Setup" --msgbox "Set a password for the socore user. This account is used for adding sensors remotely." 8 75

}

whiptail_create_socore_user_password1() {

  COREPASS1=$(whiptail --title "Security Onion Install" --passwordbox \
  "Enter a password for user socore" 10 75 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_create_socore_user_password2() {

  COREPASS2=$(whiptail --title "Security Onion Install" --passwordbox \
  "Re-enter a password for user socore" 10 75 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_cur_close_days() {

  CURCLOSEDAYS=$(whiptail --title "Security Onion Setup" --inputbox \
  "Please specify the threshold (in days) at which Elasticsearch indices will be closed" 10 75 $CURCLOSEDAYS 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}
whiptail_enable_components() {
  COMPONENTS=$(whiptail --title "Security Onion Setup" --checklist \
  "Select Components to install" 20 75 8 \
  "GRAFANA" "Enable Grafana for system monitoring" ON \
  "OSQUERY" "Enable Fleet with osquery" ON \
  "WAZUH" "Enable Wazuh" ON \
  "THEHIVE" "Enable TheHive" ON \
  "PLAYBOOK" "Enable Playbook" ON 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_eval_adv() {
  EVALADVANCED=$(whiptail --title "Security Onion Setup" --radiolist \
  "Choose your eval install:" 20 75 4 \
  "BASIC" "Install basic components for evaluation" ON  \
  "ADVANCED" "Choose additional components to be installed" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus
}

whiptail_eval_adv_warning() {
  whiptail --title "Security Onion Setup" --msgbox "Please keep in mind the more services that you enable the more RAM that is required." 8 75
}

whiptail_homenet_master() {

  # Ask for the HOME_NET on the master
  HNMASTER=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter your HOME_NET separated by ," 10 75 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_homenet_sensor() {

  # Ask to inherit from master
  whiptail --title "Security Onion Setup" --yesno "Do you want to inherit the HOME_NET from the Master?" 8 75

  local exitstatus=$?
  if [ $exitstatus == 0 ]; then
    HNSENSOR=inherit
  else
    HNSENSOR=$(whiptail --title "Security Onion Setup" --inputbox \
    "Enter your HOME_NET separated by ," 10 75 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12 3>&1 1>&2 2>&3)
    local exitstatus=$?
    whiptail_check_exitstatus $exitstatus
  fi

}

whiptail_install_type() {

  # What kind of install are we doing?
  INSTALLTYPE=$(whiptail --title "Security Onion Setup" --radiolist \
  "Choose Install Type:" 20 75 13 \
  "SENSORONLY" "Create a forward only sensor" ON \
  "STORAGENODE" "Add a Storage Hot Node with parsing" OFF \
  "MASTERONLY" "Start a new grid" OFF \
  "EVALMODE" "Evaluate all the things" OFF \
  "HELIXSENSOR" "Connect this sensor to FireEye Helix"
  "PARSINGNODE" "TODO Add a dedicated Parsing Node" OFF \
  "HOTNODE" "TODO Add Hot Node (Storage Node without Parsing)" OFF \
  "WARMNODE" "TODO Add Warm Node to existing Hot or Storage node" OFF \
  "WAZUH" "TODO Stand Alone Wazuh Node" OFF \
  "STRELKA" "TODO Stand Alone Strelka Node" OFF \
  "FLEET" "TODO Stand Alone Fleet OSQuery Node" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_log_size_limit() {

   LOG_SIZE_LIMIT=$(whiptail --title "Security Onion Setup" --inputbox \
  "Please specify the amount of disk space (in GB) you would like to allocate for Elasticsearch data storage. \
  By default, this is set to 85% of the disk space allotted for /nsm." 10 75 $LOG_SIZE_LIMIT 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}


whiptail_management_nic() {

  MNIC=$(whiptail --title "NIC Setup" --radiolist "Please select your management NIC" 20 75 12 ${NICS[@]} 3>&1 1>&2 2>&3 )
  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

  while [ -z "$MNIC" ]
  do
    MNIC=$(whiptail --title "NIC Setup" --radiolist "Please select your management NIC" 20 75 12 ${NICS[@]} 3>&1 1>&2 2>&3 )
    local exitstatus=$?
    whiptail_check_exitstatus $exitstatus
  done

}

whiptail_nids() {

  NIDS=$(whiptail --title "Security Onion Setup" --radiolist \
  "Choose which IDS to run:" 20 75 4 \
  "Suricata" "Suricata 4.X" ON  \
  "Snort" "Snort 3.0 Beta" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_oinkcode() {

  OINKCODE=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter your oinkcode" 10 75 XXXXXXX 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_make_changes() {

  whiptail --title "Security Onion Setup" --yesno "We are going to set this machine up as a $INSTALLTYPE. Please hit YES to make changes or NO to cancel." 8 75

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_management_server() {

  MSRV=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter your Master Server HOSTNAME. It is CASE SENSITIVE!" 10 75 XXXX 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

  # See if it resolves. Otherwise prompt to add to host file
  TESTHOST=$(host $MSRV)

  if [[ $TESTHOST = *"not found"* ]] || [[ $TESTHOST = *"connection timed out"* ]]; then
    add_master_hostfile
  fi

}

# Ask if you want to do advanced setup of the Master
whiptail_master_adv() {

  MASTERADV=$(whiptail --title "Security Onion Setup" --radiolist \
  "Choose what type of master install:" 20 75 4 \
  "BASIC" "Install master with recommended settings" ON  \
  "ADVANCED" "Do additional configuration to the master" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

# Ask which additional components to install
whiptail_master_adv_service_brologs() {

  BLOGS=$(whiptail --title "Security Onion Setup" --checklist "Please Select Logs to Send:" 24 75 12 \
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

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_network_notice() {

  whiptail --title "Security Onion Setup" --yesno "Since this is a network install we assume the management interface, DNS, Hostname, etc are already set up. Hit YES to continue." 8 75

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_advanced() {

  NODESETUP=$(whiptail --title "Security Onion Setup" --radiolist \
  "What type of config would you like to use?:" 20 75 4 \
  "NODEBASIC" "Install Storage Node with recommended settings" ON \
  "NODEADVANCED" "Advanced Node Setup" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_es_heap() {

  es_heapsize
  NODE_ES_HEAP_SIZE=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter ES Heap Size: \n \n(Recommended value is pre-populated)" 10 75 $ES_HEAP_SIZE 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_ls_heap() {

  ls_heapsize
  NODE_LS_HEAP_SIZE=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter LogStash Heap Size: \n \n(Recommended value is pre-populated)" 10 75 $LS_HEAP_SIZE 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_ls_pipeline_worker() {

  LSPIPELINEWORKERS=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter LogStash Pipeline Workers: \n \n(Recommended value is pre-populated)" 10 75 $CPUCORES 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_ls_pipline_batchsize() {

  LSPIPELINEBATCH=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter LogStash Pipeline Batch Size: \n \n(Default value is pre-populated)" 10 75 125 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_ls_input_threads() {

  LSINPUTTHREADS=$(whiptail --title "Security Onion Setup" --inputbox \
    "\nEnter LogStash Input Threads: \n \n(Default value is pre-populated)" 10 75 1 3>&1 1>&2 2>&3)

    local exitstatus=$?
    whiptail_check_exitstatus $exitstatus

}

whiptail_node_ls_input_batch_count() {

  LSINPUTBATCHCOUNT=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter LogStash Input Batch Count: \n \n(Default value is pre-populated)" 10 75 125 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_passwords_dont_match() {

  whiptail --title "Security Onion Setup" --msgbox "Passwords don't match. Please re-enter." 8 75

}

whiptail_patch_name_new_schedule() {

  PATCHSCHEDULENAME=$(whiptail --title "Security Onion Setup" --inputbox \
  "What name do you want to give this OS patch schedule? This schedule needs to be named uniquely. Available schedules can be found on the master under /opt/so/salt/patch/os/schedules/<schedulename>.yml" 10 75 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

  while [[ -z "$PATCHSCHEDULENAME"  ]]; do
    whiptail --title "Security Onion Setup" --msgbox "Please enter a name for this OS patch schedule." 8 75
    PATCHSCHEDULENAME=$(whiptail --title "Security Onion Setup" --inputbox \
    "What name do you want to give this OS patch schedule? This schedule needs to be named uniquely. Available schedules can be found on the master under /opt/so/salt/patch/os/schedules/<schedulename>.yml" 10 75 3>&1 1>&2 2>&3)
    local exitstatus=$?
    whiptail_check_exitstatus $exitstatus
  done


}

whiptail_patch_schedule() {

  # What kind of patch schedule are we doing?
  PATCHSCHEDULE=$(whiptail --title "Security Onion Setup" --radiolist \
  "Choose OS patch schedule. This will NOT update Security Onion related tools such as Zeek, Elasticsearch, Kibana, SaltStack, etc." 15 75 5 \
  "Automatic" "Updates installed every 8 hours if available" ON \
  "Manual" "Updates will be installed manually" OFF \
  "Import Schedule" "Import named schedule on following screen" OFF \
  "New Schedule" "Configure and name new schedule on next screen" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_patch_schedule_import() {

  unset PATCHSCHEDULENAME
  PATCHSCHEDULENAME=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter the name of the OS patch schedule you want to inherit. Available schedules can be found on the master under /opt/so/salt/patch/os/schedules/<schedulename>.yml" 10 75 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

  while [[ -z "$PATCHSCHEDULENAME"  ]]; do
    whiptail --title "Security Onion Setup" --msgbox "Please enter a name for the OS patch schedule you want to inherit." 8 75
    PATCHSCHEDULENAME=$(whiptail --title "Security Onion Setup" --inputbox \
    "Enter the name of the OS patch schedule you want to inherit. Available schedules can be found on the master under /opt/so/salt/patch/os/schedules/<schedulename>.yml" 10 75 3>&1 1>&2 2>&3)

    local exitstatus=$?
    whiptail_check_exitstatus $exitstatus
  done

}

whiptail_patch_schedule_select_days() {
   # Select the days to patch
  PATCHSCHEDULEDAYS=($(whiptail --title "Security Onion Setup" --checklist \
  "Which days do you want to apply OS patches?" 15 75 8 \
  "Monday" "" OFF \
  "Tuesday" "" ON \
  "Wednesday" "" OFF \
  "Thursday" "" OFF \
  "Friday" "" OFF \
  "Saturday" "" OFF \
  "Sunday" "" OFF 3>&1 1>&2 2>&3 ))

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus
}

whiptail_patch_schedule_select_hours() {
  # Select the hours to patch
  PATCHSCHEDULEHOURS=($(whiptail --title "Security Onion Setup" --checklist \
  "At which time, UTC, do you want to apply OS patches on the selected days? Hours 12 through 23 can be selected on the next screen." 22 75 13 \
  "00:00" "" OFF \
  "01:00" "" OFF \
  "02:00" "" OFF \
  "03:00" "" OFF \
  "04:00" "" OFF \
  "05:00" "" OFF \
  "06:00" "" OFF \
  "07:00" "" OFF \
  "08:00" "" OFF \
  "09:00" "" OFF \
  "10:00" "" OFF \
  "11:00" "" OFF 3>&1 1>&2 2>&3 ))

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

  # Select the hours to patch
  PATCHSCHEDULEHOURS+=($(whiptail --title "Security Onion Setup" --checklist \
  "At which time, UTC, do you want to apply OS patches on the selected days?" 22 75 13 \
  "12:00" "" OFF \
  "13:00" "" OFF \
  "14:00" "" OFF \
  "15:00" "" ON \
  "16:00" "" OFF \
  "17:00" "" OFF \
  "18:00" "" OFF \
  "19:00" "" OFF \
  "20:00" "" OFF \
  "21:00" "" OFF \
  "22:00" "" OFF \
  "23:00" "" OFF 3>&1 1>&2 2>&3 ))

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus
}

whiptail_rule_setup() {

  # Get pulled pork info
  RULESETUP=$(whiptail --title "Security Onion Setup" --radiolist \
  "What IDS rules to use?:" 20 75 4 \
  "ETOPEN" "Emerging Threats Open - no oinkcode required" ON \
  "ETPRO" "Emerging Threats PRO - requires ETPRO oinkcode" OFF \
  "TALOSET" "Snort Subscriber (Talos) ruleset and Emerging Threats NoGPL ruleset - requires Snort Subscriber oinkcode" OFF \
  "TALOS" "Snort Subscriber (Talos) ruleset only and set a Snort Subscriber policy - requires Snort Subscriber oinkcode" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_sensor_config() {

  NSMSETUP=$(whiptail --title "Security Onion Setup" --radiolist \
  "What type of configuration would you like to use?:" 20 75 4 \
  "BASIC" "Install NSM components with recommended settings" ON \
  "ADVANCED" "Configure each component individually" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_set_hostname() {

  HOSTNAME=$(whiptail --title "Security Onion Setup" --inputbox \
  "Enter the Hostname you would like to set." 10 75 $HOSTNAME 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

  while [[ "$HOSTNAME" == 'localhost' ]] ; do
    whiptail --title "Security Onion Setup" --msgbox "Please choose a hostname that isn't localhost." 8 75
    HOSTNAME=$(whiptail --title "Security Onion Setup" --inputbox \
    "Enter the Hostname you would like to set." 10 75 $HOSTNAME 3>&1 1>&2 2>&3)
    local exitstatus=$?
    whiptail_check_exitstatus $exitstatus
  done

}

whiptail_setup_complete() {

  whiptail --title "Security Onion Setup" --msgbox "Finished installing this as an $INSTALLTYPE. Press Enter to reboot." 8 75
  install_cleanup

}

whiptail_setup_failed() {

  whiptail --title "Security Onion Setup" --msgbox "Install had a problem. Please see $SETUPLOG for details. Press Enter to reboot." 8 75
  install_cleanup

}

whiptail_shard_count() {

  SHARDCOUNT=$(whiptail --title "Security Onion Setup" --inputbox \
  "\nEnter ES Shard Count: \n \n(Default value is pre-populated)" 10 75 125 3>&1 1>&2 2>&3)

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_suricata_pins() {

  FILTEREDCORES=$(echo ${LISTCORES[@]} ${BROPINS[@]} | tr -d '"' | tr ' ' '\n' | sort | uniq -u | awk '{print $1 " \"" "core" "\""}')
  SURIPINS=$(whiptail --noitem --title "Pin Suricata CPUS" --checklist "Please Select $LBPROCS cores to pin Suricata to:" 20 75 12 ${FILTEREDCORES[@]} 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_master_updates() {

  MASTERUPDATES=$(whiptail --title "Security Onion Setup" --radiolist \
  "How would you like to download updates for your grid?:" 20 75 4 \
  "MASTER" "Master node is proxy for OS/Docker updates." ON \
  "OPEN" "Each node connect to the Internet for updates" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_node_updates() {

  NODEUPDATES=$(whiptail --title "Security Onion Setup" --radiolist \
  "How would you like to download updates for this node?:" 20 75 4 \
  "MASTER" "Download OS/Docker updates from the Master." ON \
  "OPEN" "Download updates directly from the Internet" OFF 3>&1 1>&2 2>&3 )

  local exitstatus=$?
  whiptail_check_exitstatus $exitstatus

}

whiptail_you_sure() {

  echo "whiptail_you_sure called" >> $SETUPLOG 2>&1
  whiptail --title "Security Onion Setup" --yesno "Are you sure you want to install Security Onion over the internet?" 8 75

  local exitstatus=$?
  echo "whiptail_you_sure returning $exitstatus" >> $SETUPLOG 2>&1
  return $exitstatus

}
