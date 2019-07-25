## Hybrid Hunter Alpha 1.1.0

### Changes:

- Alpha is here!! Check out the [Hybrid Hunter Quick Start Guide](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/Hybrid-Hunter-Quick-Start-Guide).
- There is a new PCAP interface called [Sensoroni](https://github.com/sensoroni/sensoroni). You can [pivot directly from Kibana to Sensoroni via the _id field](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/Pulling-PCAP).
- Bond interface setup now uses `nmcli` for better compatibility in the network based setup script.
- Filebeat traffic for HH components now use a separate port (5644). This will allow you to send Beats to the default port (5044) and choose how you want to secure it. It is still recommended to use full SSL via Filebeat and if you already have this set up you will need to change to port 5044. We will continue to refine this in future versions.
- Authentication is now enabled by default for all the web based components. There will be some major changes before we get to beta with how authentication in general is handled due to Elastic "Features" and other components.
- Add users to the web interface via `so-user-add` and follow the prompts.
- `so-allow` now exists to make your life easier.
- Bro 2.6.2.
- All Docker images were updated to reflect Alpha status.
- Disabled DEBUG logging on a lot of components to reduce space usage.
- Added a rule update cron job so the master pulls new rules down every day at 7AM UTC.
- You can now manually run a rule update using the `so-rule-update` command.

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

### FAQ
See the [FAQ](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/FAQ) on the Hybrid Hunter wiki.

### Feedback
If you have questions, problems, or other feedback regarding Hybrid Hunter, please post to our subreddit and prefix the title with **[Hybrid Hunter]**:<br>
https://www.reddit.com/r/securityonion/
