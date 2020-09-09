{% set MANAGER = salt['grains.get']('master') %}
airgapyum:
  file.managed:
    - name: /etc/yum/yum.conf
    - source: salt://airgap/files/yum.conf

airgap_repo:
  pkgrepo.managed:
    - humanname: Airgap Repo
    - baseurl: https://{{ MANAGER }}/repo
    - gpgcheck: 0
    - sslverify: 0

agbase:
  file.absent:
    - name: /etc/yum.repos.d/CentOS-Base.repo

agcr:
  file.absent:
    - name: /etc/yum.repos.d/CentOS-CR.repo

agdebug:
  file.absent:
    - name: /etc/yum.repos.d/CentOS-Debuginfo.repo

agfasttrack:
  file.absent:
    - name: /etc/yum.repos.d/CentOS-fasttrack.repo

agmedia:
  file.absent:
    - name: /etc/yum.repos.d/CentOS-Media.repo

agsources:
  file.absent:
    - name: /etc/yum.repos.d/CentOS-Sources.repo

agvault:
  file.absent:
    - name: /etc/yum.repos.d/CentOS-Vault.repo

agkernel:
  file.absent:
    - name: /etc/yum.repos.d/CentOS-x86_64-kernel.repo

agepel:
  file.absent:
    - name: /etc/yum.repos.d/epel.repo

agtesting:
  file.absent:
    - name: /etc/yum.repos.d/epel-testing.repo

agssrepo:
  file.absent:
    - name: /etc/yum.repos.d/saltstack.repo

agwazrepo:
  file.absent:
    - name: /etc/yum.repos.d/wazuh.repo