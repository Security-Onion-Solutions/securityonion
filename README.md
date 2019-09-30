## Hybrid Hunter Alpha 1.1.1

### Changes:

- Alpha 2 is here!! Check out the [Hybrid Hunter Quick Start Guide](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/Hybrid-Hunter-Quick-Start-Guide).  
- Suricata 4.1.5.  
- Bro/Zeek 2.6.4.  
- TheHive 3.4.0 (Includes ES 6.8.3 for TheHive only).
- Fixed Bro/Zeek packet loss calculation for Grafana.
- Updated to latest Sensoroni for websockets to enable job status updates without refreshing.
- NIDS and HIDS dashboard updates.
- Playbook and ATT&CK Navigator features are now included.
- Filebeat now logs to a file, instead of stdout.
- Elastalert has been updated to use Python 3 and allow for use of custom alerters.  
- Elasticsearch Ingest is now used to consume Zeek logs and Suricata alerts (instead of the traditional Logstash pipeline).
  This reduces the memory footprint of Logstash dramatically!  
- Several changes to the setup script have been made to improve stability of the setup process:  
  - Setup now modifies your hosts file so that the install works better in environments without DNS.  
  - You are now prompted for setting a password for the socore user.  
  - The install now forces a reboot at the end of the install. This fixes an issue with some of the Docker containers being in the wrong state from a manual reboot. Manual reboots are fine after the initial reboot.


### Warnings and Disclaimers

- This ALPHA release is BLEEDING EDGE and TOTALLY UNSUPPORTED!  
- If this breaks your system, you get to keep both pieces!  
- This script is a work in progress and is in constant flux.  
- This script is intended to build a quick prototype proof of concept so you can see what our new platform might look like.  This configuration will change drastically over time leading up to the final release.  
- Do NOT run this on a system that you care about!  
- Do NOT run this on a system that has data that you care about!  
- This script should only be run on a TEST box with TEST data!  
- Use of this script may result in nausea, vomiting, or a burning sensation.  

### Requirements

Evaluation Mode:

- Single VM running Ubuntu 16.04 or CentOS 7
- Minimum 8GB of RAM
- Minimum 4 CPU cores
- Minimum 2 NICs

Distributed:

- 3 VMs running Ubuntu 16.04 or CentOS 7 (You can mix and match)
- Minimum 8GB of RAM per VM
- Minimum 4 CPU cores per VM
- Minimum 2 NICs for forward nodes

### Prerequisites

If you are running CentOS 7 there are a couple of prerequisites:

```
sudo yum -y install git bind-utils
sudo hostnamectl set-hostname YOURHOSTNAME
sudo reboot
```

If you are running CentOS 7 or Ubuntu 16.04 and don't have name resolution ensure your `/etc/hosts` file looks like this:

```
127.0.0.1   YOURHOSTNAME YOURHOSTNAME.localdomain localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
```  
It is imperative that YOURHOSTNAME.localdomain is included in this hosts entry for the install to complete properly.


### Installation

Once you resolve those requirements or are using Ubuntu 16.04 do the following:

```
git clone https://github.com/Security-Onion-Solutions/securityonion-saltstack
cd securityonion-saltstack
sudo bash so-setup-network.sh
```
Follow the prompts and reboot if asked to do so.

Then proceed to the [Hybrid Hunter Quick Start Guide](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/Hybrid-Hunter-Quick-Start-Guide).

### FAQ
See the [FAQ](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/FAQ) on the Hybrid Hunter wiki.

### Feedback
If you have questions, problems, or other feedback regarding Hybrid Hunter, please post to our subreddit and prefix the title with **[Hybrid Hunter]**:<br>
https://www.reddit.com/r/securityonion/
