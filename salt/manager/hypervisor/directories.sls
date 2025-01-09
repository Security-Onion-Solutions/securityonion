{% set dirs = [
  '/nsm/libvirt/createvm'
] %}

create_libvirt_dirs:
  file.directory:
    - names: {{ dirs }}
    - makedirs: True
    - mode: 755
    - user: root
    - group: root
