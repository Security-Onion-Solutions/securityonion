## Hybrid Hunter Alpha 1.1.4 - Feature Parity Release

### Changes:

- Added new in-house auth method [Security Onion Auth](https://github.com/Security-Onion-Solutions/securityonion-auth).
- Web user creation is done via the browser now instead of so-user-add.
- New Logstash pipeline setup. Now uses multiple pipelines.
- New Master + Search node type and well as a Heavy Node type in the install. 
- Change all nodes to point to the docker registry on the Master. This cuts down on the calls to dockerhub.
- Zeek 3.0.1
- Elastic 6.8.6
- New SO Start | Stop | Restart scripts for all components (eg. `so-playbook-restart`).
- BPF support for Suricata (NIDS), Steno (PCAP) & Zeek ([Docs](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/BPF)).
- Updated Domain Stats & Frequency Server containers to Python3 & created new Salt states for them.
- Added so-status script which gives an easy to read look at container status.
- Manage threshold.conf for Suricata using the thresholding pillar.
- The ISO now includes all the docker containers for faster install speeds.
- You now set the password for the onion account during the iso install. This account is temporary and will be removed after so-setup. 
- Updated Helix parsers for better compatibility.
- Updated telegraf docker to include curl and jq.
- CVE-2020-0601 Zeek Detection Script. 
- ISO Install now prompts you to create a password for the onion user during imaging. This account gets disabled during setup.


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
