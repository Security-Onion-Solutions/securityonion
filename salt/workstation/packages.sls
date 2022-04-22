{# we only want this state to run it is CentOS #}
{% if grains.os == 'CentOS' %}

xwindows_group:
  pkg.group_installed:
    - name: X Window System

graphical_extras:
  pkg.installed:
    - pkgs:
      - gnome-classic-session
      - gnome-terminal
      - gnome-terminal-nautilus
      - control-center
      - liberation-mono-fonts
      - file-roller

workstation_packages:
  pkg.installed:
    - pkgs:
      - wget
      - curl
      - unzip
      - gedit
      - mono-core
      - mono-basic
      - mono-winforms
      - expect
      - wireshark-gnome
      - dsniff
      - hping3
      - netsed
      - ngrep
      - python36-scapy
      - ssldump
      - tcpdump
      - tcpflow
      - whois
      - chromium
      - libevent
      - sslsplit
      - perl-IO-Compress 
      - perl-Net-DNS
      - securityonion-networkminer
      - securityonion-chaosreader
      - securityonion-analyst-extras
      - securityonion-bittwist
      - securityonion-tcpstat
      - securityonion-tcptrace
      - securityonion-foremost
      - securityonion-strelka-oneshot
      - securityonion-strelka-fileshot

{% else %}

workstation_packages_os_fail:
  test.fail_without_changes:
    - comment: 'SO Analyst Workstation can only be installed on CentOS'

{% endif %}
