# Security Onion Hybrid Hunter Tech Preview 1.0.1

### Warnings and Disclaimers

- This technology PREVIEW is PRE-ALPHA, BLEEDING EDGE, and TOTALLY UNSUPPORTED!  
- If this breaks your system, you get to keep both pieces!  
- This script is a work in progress and is in constant flux.  
- This script is intended to build a quick prototype proof of concept so you can see what our new platform might look like.  This configuration will change drastically over time leading up to the final - release.  
- Do NOT run this on a system that you care about!  
- Do NOT run this on a system that has data that you care about!  
- This script should only be run on a TEST box with TEST data!  
- This script is only designed for standalone boxes and does NOT support distributed deployments.  
- Use of this script may result in nausea, vomiting, or a burning sensation.  

### Requirements

Evaluation Mode:

- Single Ubuntu 16.04 or CentOS 7 VM
- Minimum 8GB of RAM
- Minimum 4 CPU cores
- Minimum 2 NICs

Distributed:

- 3 VMs running Ubuntu 16.04 or CentOS 7 (You can mix and match)
- Minimum 8GB of RAM per VM
- Minimum 4 CPU cores per VM
- Minimum 2 NICs for forward nodes

### Prerequisites

If you are using CentOS 7 there are a couple of prerequisites:

```
sudo yum -y install bind-utils
sudo hostnamectl set-hostname YOURHOSTNAME
sudo reboot
```

### Installation

Once you resolve those requirements or are using Ubuntu 16.04 do the following:

```
git clone https://github.com/Security-Onion-Solutions/securityonion-saltstack
cd securityonion-saltstack
sudo bash so-setup-network.sh
```

### Allow Access to Kibana

For a single host:
```
sudo /opt/so/saltstack/pillar/firewall/addfirewall.sh analyst 192.168.30.1
```
For a network range:
```
sudo /opt/so/saltstack/pillar/firewall/addfirewall.sh analyst 192.168.30.0/24
```
Then connect to your master via https://YOURMASTER

### FAQ
See the [FAQ](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/FAQ) on the Hybrid Hunter wiki.

### Feedback
If you have questions, problems, or other feedback regarding Hybrid Hunter, please post to our subreddit and prefix the title with [Hybrid Hunter]:

https://www.reddit.com/r/securityonion/
