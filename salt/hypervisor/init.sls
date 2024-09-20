hypervisor_log_dir:
  file.directory:
    - name: /opt/so/log/hypervisor

hypervisor_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://hypervisor/tools/sbin
    - file_mode: 744
