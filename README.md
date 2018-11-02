# Security Onion Hybrid Hunter Tech Preview

Installation:

If you are using CentOS 7 there are a couple pre-requisites:

```
sudo yum -y install bind-utils
sudo hostnamectl set-hostname YOURHOSTNAME
sudo reboot
```
Once you resolve those requirements or are using Ubuntu do the following:

```
git clone https://github.com/Security-Onion-Solutions/securityonion-saltstack
cd securityonion-saltstack
sudo bash so-setup-network.sh
```
Allow Access to Kibana:

For a single host:
```
sudo /opt/so/saltstack/pillar/firewall/addfirewall.sh analyst 192.168.30.1
```
For a network range:
```
sudo /opt/so/saltstack/pillar/firewall/addfirewall.sh analyst 192.168.30.0/24
```
Then connect to your master via https://YOURMASTER

See the [FAQ](https://github.com/Security-Onion-Solutions/securityonion-saltstack/wiki/FAQ) on the Hybrid Hunter wiki.
