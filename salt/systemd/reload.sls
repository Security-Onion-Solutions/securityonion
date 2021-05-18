systemd_reload:
  module.run:
    - service.systemctl_reload: []