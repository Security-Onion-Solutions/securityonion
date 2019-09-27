## Hybrid Hunter Alpha 1.1.1

### Changes:

- Alpha 2 is here!! Check out the [Hybrid Hunter Quick Start Guide](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/Hybrid-Hunter-Quick-Start-Guide).  
- Suricata 4.1.5  
- Bro/Zeek 2.6.4  
- Fixed an issue where the filbeat docker was logging to stdout instead of the actual log file causing the docker to get extremely large.  
- Now using elastic ingest for zeek logs and suricata alerts. This reduces the memory footprint of logstash dramatically!  
- Several changes to the setup script to improve installation success:  
  - Setup now modifes your hosts file so that the install works better in environments without DNS.  
  - You are now prompted for setting a password for the socore user.  
  - The install now forces a reboot at the end of the install. This fixes an issue with some of the docker containers being in the wrong state from a manual reboot. Manual reboots are fine after the initial reboot.
- Updated The Hive to 3.4.0 and the ES instance to 6.8.3.  
- NIDS and HIDS dashboard updates.
- Added new Playbook and Navigator features.


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
