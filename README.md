## Hybrid Hunter Beta 1.4.1 - Beta 3

- Fix install script to handle hostnames properly.


## Hybrid Hunter Beta 1.4.0 - Beta 3

- Complete overhaul of the way we handle custom and default settings and data. You will now see a default and local directory under the saltstack directory. All customizations are stored in local.
- The way firewall rules are handled has been completely revamped. This will allow the user to customize firewall rules much easier. 
- Users can now change their own password in SOC.
- Hunt now allows users to enable auto-hunt. This is a toggle which, when enabled, automatically submits a new hunt when filtering, grouping, etc.
- Title bar now reflects current Hunt query. This will assist users in locating a previous query from their browser history.
- Zeek 3.0.7
- Elastic 7.7.1
- Suricata can now be used for meta data generation.
- Suricata eve.json has been moved to `/nsm` to align with storage of other data.
- Suricata will now properly rotate its logs.
- Grafana dashboards now work properly in standalone mode.
- Kibana Dashboard updates including osquery, community_id.  
- New Elasticsearch Ingest processor to generate community_id from any log that includes the required fields.  
- Community_id generated for additional logs: Zeek HTTP/SMTP/ , Sysmon shipped with Osquery or Winlogbeat.  
- Major streamlining of Fleet setup & configuration - no need to run a secondary setup script anymore. 
- Fleet Standalone node now includes the ability to set a FQDN to point osquery endpoints to. 
- Distributed installs now support ingesting Windows Eventlogs via Winlogbeat - includes full parsing support for Sysmon.
- SOC Downloads section now includes a link to the supported version of Winlogbeat.     
- Basic syslog ingestion capability now included.
- Elasticsearch index name transition fixes for various components.
- Updated URLs for pivot fields in Kibana.
- Instances of `hive` renamed to `thehive`. 
 
### Known Issues:

- The Hunt feature is currently considered "Preview" and although very useful in its current state, not everything works. We wanted to get this out as soon as possible to get the feedback from you! Let us know what you want to see! Let us know what you think we should call it!
- You cannot pivot to PCAP from Suricata alerts in Kibana or Hunt.
- Navigator is currently not working when using hostname to access SOC. IP mode works correctly.
- Due to the move to ECS, the current Playbook plays may not alert correctly at this time.
- The osquery MacOS package does not install correctly.


## Hybrid Hunter Beta 1.3.0 - Beta 2

### Changes:

- New Feature: Codename: "Onion Hunt". Select Hunt from the menu and start hunting down your adversaries! 
- Improved ECS support.
- Complete refactor of the setup to make it easier to follow.
- Improved setup script logging to better assist on any issues.
- Setup now checks for minimal requirements during install.
- Updated Cyberchef to version 9.20.3.
- Updated Elastalert to version 0.2.4 and switched to alpine to reduce container size.
- Updated Redis to 5.0.9 and switched to alpine to reduce container size.
- Updated Salt to 2019.2.5
- Updated Grafana to 6.7.3.
- Zeek 3.0.6
- Suricata 4.1.8
- Fixes so-status to now display correct containers and status.
- local.zeek is now controlled by a pillar instead of modifying the file directly.
- Renamed so-core to so-nginx and switched to alpine to reduce container size.
- Playbook now uses MySQL instead of SQLite.
- Sigma rules have all been updated.
- Kibana dashboard improvements for ECS.
- Fixed an issue where geoip was not properly parsed.
- ATT&CK Navigator is now it's own state.
- Standlone mode is now supported.
- Mastersearch previously used the same Grafana dashboard as a Search node. It now has its own dashboard that incorporates panels from the Master node and Search node dashboards.
 
### Known Issues:

- The Hunt feature is currently considered "Preview" and although very useful in its current state, not everything works. We wanted to get this out as soon as possible to get the feedback from you! Let us know what you want to see! Let us know what you think we should call it!
- You cannot pivot to PCAP from Suricata alerts in Kibana or Hunt.
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
