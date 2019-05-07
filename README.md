## Hybrid Hunter 1.0.8

### Changes:

- Suricata 4.1.4
- Eval and Master installs now ask which components you would like to install
- Fleet (osquery) now has it's own additional setup script. [See the docs](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/Configuring-Osquery-with-Security-Onion)
- Fleet setup script now generates auto install packages for Windows, CentOS, and Ubuntu
- When Fleet setup is completed, all SO nodes will auto install the appropriate auto install package
- We now have a progress bar during install!
- The setup script will now tell you if it was successful
- Added Grafana plugin Pie Chart
- The Hive Docker moved to Centos 7 based container
=======
- Suricata 4.1.3
- Updated Influxdb to 1.7.5
- Updated Telegraf to 1.10.1
- Grafana is now 6.0.2
- Added support for TheHive! To enable, please see https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/The-Hive
- You are now forced to select interfaces during setup. If you skipped this test the install was not happy [#26](https://github.com/Security-Onion-Solutions/securityonion-saltstack/issues/26)
- Reduced the RAM usage for ES in Eval mode [#25](https://github.com/Security-Onion-Solutions/securityonion-saltstack/issues/26)
- Eval Mode setup is now choose your own adventure style
- Fresh dockers for all the things to bring everything to 1.0.7
- New utility docker called SOctopus
- New html landing page now in dark mode


### Notes:
- Attempting to send a Bro event to The Hive that does not contain a source and destination IP (ex. Bro files, or X509) will result in an exception - a fix for this will be implemented in the next release.
- If attempting to pivot from Kibana, ensure that you can resolve the master via DNS -- otherwise, populate your local hosts file with an entry to point to the master.


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

### Installation

Once you resolve those requirements or are using Ubuntu 16.04 do the following:

```
git clone https://github.com/Security-Onion-Solutions/securityonion-saltstack
cd securityonion-saltstack
sudo bash so-setup-network.sh
```
Follow the prompts and reboot if asked to do so.

Want to try the bleeding edge? You can install the following:
```
git clone https://github.com/TOoSmOotH/securityonion-saltstack
cd securityonion-saltstack
sudo bash so-setup-network.sh
```
This is an active development repo so many things can and will be broken.

### Allow Access to Kibana
Once Setup is complete and services have initialized, you can then allow access to Kibana as follows.

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
If you have questions, problems, or other feedback regarding Hybrid Hunter, please post to our subreddit and prefix the title with **[Hybrid Hunter]**:<br>
https://www.reddit.com/r/securityonion/
