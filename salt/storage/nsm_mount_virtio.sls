# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# Install required packages
storage_nsm_mount_virtio_packages:
  pkg.installed:
    - pkgs:
      - xfsprogs

# Ensure log directory exists
storage_nsm_mount_virtio_logdir:
  file.directory:
    - name: /opt/so/log
    - makedirs: True
    - user: root
    - group: root
    - mode: 755

# Install the NSM mount script
storage_nsm_mount_virtio_script:
  file.managed:
    - name: /usr/sbin/so-nsm-mount-virtio
    - source: salt://storage/tools/sbin/so-nsm-mount-virtio
    - mode: 755
    - user: root
    - group: root
    - require:
      - pkg: storage_nsm_mount_virtio_packages
      - file: storage_nsm_mount_virtio_logdir

# Execute the mount script if not already mounted
storage_nsm_mount_virtio_execute:
  cmd.run:
    - name: /usr/sbin/so-nsm-mount-virtio
    - unless: mountpoint -q /nsm
    - require:
      - file: storage_nsm_mount_virtio_script
