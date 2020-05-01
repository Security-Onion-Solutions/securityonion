## Hybrid Hunter Beta 1.2.2 - Beta 1

### Changes:  

- Updated Saltstack to 2019.2.4 to address [CVE-2020-11651](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11651)
- Updated Suricata to 4.1.8 to address some possible security issues. Details [here](https://suricata-ids.org/2020/04/28/suricata-4-1-8-released/).
- Fixed an issue that was preventing Strelka to function properly.
- ISO installs should now use the built in docker containers instead of re-downloading them.


## Hybrid Hunter Beta 1.2.1 - Beta 1

### Changes:

- Full support for Ubuntu 18.04. 16.04 is no longer supported for Hybrid Hunter.
- Introduction of the Security Onion Console. Once logged in you are directly taken to the SOC.
- New authentication using Kratos.
- During install you must specify how you would like to access the SOC ui. This is for strict cookie security.
- Ability to list and delete web users from the SOC ui.
- The soremote account is now used to add nodes to the grid vs using socore. 
- Community ID support for Zeek, osquery, and Suricata. You can now tie host events to connection logs!
- Elastic 7.6.1 with ECS support.
- New set of Kibana dashboards that align with ECS.
- Eval mode no longer uses Logstash for parsing (Filebeat -> ES Ingest)
- Ingest node parsing for osquery-shipped logs (osquery, WEL, Sysmon).
- Fleet standalone mode with improved Web UI & API access control.
- Improved Fleet integration support.
- Playbook now has full Windows Sigma community ruleset builtin.
- Automatic Sigma community rule updates.
- Playbook stability enhancements.
- Zeek health check. Zeek will now auto restart if a worker crashes.
- zeekctl is now managed by salt.
- Grafana dashboard improvements and cleanup.
- Moved logstash configs to pillars.
- Salt logs moved to /opt/so/log/salt.
- Strelka integrated for file-oriented detection/analysis at scale

### Known issues:

- Updating users via the SOC ui is known to fail. To change a user, delete the user and re-add them. 
- Due to the move to ECS, the current Playbook plays may not alert correctly at this time.
- The osquery MacOS package does not install correctly.

### Warnings and Disclaimers

- This BETA release is BLEEDING EDGE and TOTALLY UNSUPPORTED!  
- If this breaks your system, you get to keep both pieces!  
- This script is a work in progress and is in constant flux.  
- This script is intended to build a quick prototype proof of concept so you can see what our new platform might look like.  This configuration will change drastically over time leading up to the final release.  
- Do NOT run this on a system that you care about!  
- Do NOT run this on a system that has data that you care about!  
- This script should only be run on a TEST box with TEST data!  
- Use of this script may result in nausea, vomiting, or a burning sensation.  

### Requirements

Evaluation Mode:

- ISO or a Single VM running Ubuntu 18.04 or CentOS 7
- Minimum 12GB of RAM
- Minimum 4 CPU cores
- Minimum 2 NICs

Distributed:

- 3 VMs running the ISO or Ubuntu 18.04 or CentOS 7 (You can mix and match)
- Minimum 8GB of RAM per VM
- Minimum 4 CPU cores per VM
- Minimum 2 NICs for forward nodes

### Installation

For most users, we recommend installing using [our ISO image](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/ISO).

If instead you would like to try a manual installation (not using our ISO), you can build from CentOS 7 or Ubuntu 18.04.

If using CentOS 7 Minimal, you will need to install git:

```sudo yum -y install git```

Once you have git, then do the following:

```
git clone https://github.com/Security-Onion-Solutions/securityonion-saltstack
cd securityonion-saltstack
sudo bash so-setup-network
```

Follow the prompts and reboot if asked to do so.

Then proceed to the [Hybrid Hunter Quick Start Guide](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/Hybrid-Hunter-Quick-Start-Guide).

### FAQ
See the [FAQ](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/FAQ) on the Hybrid Hunter wiki.

### Feedback
If you have questions, problems, or other feedback regarding Hybrid Hunter, please post to our subreddit and prefix the title with **[Hybrid Hunter]**:<br>
https://www.reddit.com/r/securityonion/
