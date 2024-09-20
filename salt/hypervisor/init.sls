hypervisor_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://hypervisor/tools/sbin
    - file_mode: 744
