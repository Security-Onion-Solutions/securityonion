# we cannot import GLOBALS from vars/globals.map.jinja in this state since it is called in setup.virt.init
# since it is early in setup of a new VM, the pillars imported in GLOBALS are not yet defined

remove_mariadb:
  pkg.removed:
    - name: mariadb-devel

commonpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - python3-dnf-plugin-versionlock
      - bc
      - curl
      - device-mapper-persistent-data
      - fuse
      - fuse-libs
      - fuse-overlayfs
      - fuse-common
      - fuse3
      - fuse3-libs
      - git
      - httpd-tools
      - jq
      - lvm2
      - net-tools
      - nmap-ncat
      - procps-ng
{# OL10 test path: python3-docker / python3-m2crypto are not packaged in EPEL 10 and are not
   referenced by SO code (salt uses its bundled docker module from salt/python_modules.sls).
   python3-rich is also unavailable on EL10 (its pygments dep is not packaged), so it is
   installed via pip below. Gate on the grain because GLOBALS/pillars are not available this
   early (see header note). #}
{% if grains['osmajorrelease']|int < 10 %}
      - python3-docker
      - python3-m2crypto
      - python3-rich
{% else %}
      - python3-pip
{% endif %}
      - python3-packaging
      - python3-pyyaml
      - rsync
      - sqlite
      - tcpdump
      - unzip
      - wget
      - yum-utils

{% if grains['osmajorrelease']|int >= 10 %}
# OL10 test path: rich is not packaged for EL10; install it into the system python3 for so-status.
commonpkgs_pip_rich:
  cmd.run:
    - name: python3 -m pip install rich
    - unless: python3 -c "import rich"
    - require:
      - pkg: commonpkgs
{% endif %}
