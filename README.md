## Hybrid Hunter Alpha 1.1.2

- Quick firewall fix to address latest docker version.
- Added the option to install playbook from the initial install.
- Fixed an issue with multiple monitor interfaces not working properly.  

ISO Download: [HH 1.1.2-2](https://github.com/Security-Onion-Solutions/securityonion-hh-iso/releases/download/HH1.1.2/HH-1.1.2-2.iso)  
(Hashes for HH-1.1.2-2.iso)
MD5 = ABBBAE7B40A50623546ED3D7F8CDA0EC  
SHA1 = 3122C564E616BFF529B80BB06447759D775A5B1D
SHA256 = E9AD121F62C72B70D53C7DFD07178FDA6E28D97086036C632A7DD68F7C2172D6

## Hybrid Hunter Alpha 1.1.1

### Changes:

- Alpha 2 is here!
- Suricata 4.1.5.  
- Bro/Zeek 2.6.4.  
- TheHive 3.4.0 (Includes ES 6.8.3 for TheHive only).
- Fixed Bro/Zeek packet loss calculation for Grafana.
- Updated to latest Sensoroni which includes websockets support for job status updates without having to refresh the page.
- NIDS and HIDS dashboard updates.
- Playbook and ATT&CK Navigator features are now included.
- Filebeat now logs to a file, instead of stdout.
- Elastalert has been updated to use Python 3 and allow for use of custom alerters.  
- Moved Bro/Zeek log parsing from Logstash to Elasticsearch Ingest for higher performance and lower memory usage!
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
