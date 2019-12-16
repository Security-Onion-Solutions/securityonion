## Hybrid Hunter Alpha 1.1.3

### ISO Download:

[HH1.1.3-20.iso](https://github.com/Security-Onion-Solutions/securityonion-hh-iso/releases/download/HH1.1.3/HH-1.1.3-20.iso)  
MD5: 5A97980365A2A63EBFABB8C1DEB32BB6  
SHA1: 2A780B41903D907CED91D944569FD24FC131281F  
SHA256: 56FA65EB5957903B967C16E792B17386848101CD058E0289878373110446C4B2

```
Default Username: onion
Default Password: V@daL1aZ
```

### Changes:

- Overhaul of the setup script to support both ISO and network based setups.
- ISO will now boot properly from a USB stick.
- Python 3 is now default.
- Fix Filebeat from restarting every check in due to x509 refresh issue. 
- Cortex installed and integrated with TheHive. 
- Switched to using vanilla Kolide Fleet and upgraded to latest version (2.4) .  
- Playbook changes:
  - Now preloaded with Plays generated from Sysmon Sigma signatures in the [Sigma community repo](https://github.com/Neo23x0/sigma/tree/master/rules/windows/sysmon).  
  - New update script that updates / pulls in new Sigma signatures from the community repo .
  - Bulk enable / disable plays from the webui . 
  - Updated sigmac mapping template & configuration (backend is now `elastalert`) . 
  - Updated TheHive alerts formatting . 
- OS patch scheduling:
  - During setup, choose between auto, manual, or scheduled OS patch interval
  - For scheduled, create a new or import an existing named schedule



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

- ISO or a Single VM running Ubuntu 16.04 or CentOS 7
- Minimum 12GB of RAM
- Minimum 4 CPU cores
- Minimum 2 NICs

Distributed:

- 3 VMs running the ISO or Ubuntu 16.04 or CentOS 7 (You can mix and match)
- Minimum 8GB of RAM per VM
- Minimum 4 CPU cores per VM
- Minimum 2 NICs for forward nodes

### Prerequisites for Network Based Install

Install git if using a Centos 7 Minimal install:

```sudo yum -y install git```

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
