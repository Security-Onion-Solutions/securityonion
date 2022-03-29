include:
  - workstation.packages

graphical_target:
  file.symlink:
    - name: /etc/systemd/system/default.target
    - target: /lib/systemd/system/graphical.target
    - force: True
    - require:
      - pkg: X Window System
      - pkg: graphical_extras
