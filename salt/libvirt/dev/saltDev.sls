# This state is designed to run on a development manager running in a libvirt VM. It will map the default pillar and salt directories
# from /opt/so/saltstack/default to your local development machine as the source path.
# The VM requires a filesystem to be added. Only the source path should be changed to your development codebase
#  Driver: virtio-9p
#  Source path: ~/project/securityonion
#  Target path: saltDev

# If you want a directory to be RW, then kvm must have group privileges.
# ll /home/user/projects/securityonion/salt/hypervisor
# total 48
# drwxrwxr-x  3 user kvm 4096 Feb 13 11:18 ./
# drwxrwxr-x 64 user user 4096 Feb 13 10:32 ../
# -rw-rw-r--  1 user kvm 2238 Feb 12 15:06 defaults.yaml
# -rw-rw-r--  1 user kvm 1467 Feb 12 15:06 init.sls
# -rw-rw-r--  1 user kvm   70 Feb 13 09:37 soc_hypervisor.yaml
# drwxrwxr-x  3 user kvm 4096 Feb 12 15:06 tools/

# Ensure required kernel modules are configured for loading
/etc/modules-load.d/virtio-9p.conf:
  file.managed:
    - contents: |
        9pnet_virtio
        9pnet
        9p
    - mode: 644
    - user: root
    - group: root

# Load the kernel modules immediately (in the correct order)
load_9p_modules:
  cmd.run:
    - names:
      - modprobe 9pnet_virtio
      - modprobe 9pnet
      - modprobe 9p
    - unless: lsmod | grep -E '9pnet_virtio|9pnet|9p'

# Ensure mount point exists
/opt/so/saltstack/default:
  file.directory:
    - user: root
    - group: root
    - mode: 755
    - makedirs: True

# Configure fstab entry using mount.fstab_present
# Configure fstab entry using mount.fstab_present
saltdev_fstab:
  mount.fstab_present:
    - name: saltDev
    - fs_file: /opt/so/saltstack/default
    - fs_vfstype: 9p
    - fs_mntops: _netdev,trans=virtio,version=9p2000.L
    - fs_freq: 0
    - fs_passno: 0

# Mount the filesystem if not already mounted
mount_saltdev:
  mount.mounted:
    - name: /opt/so/saltstack/default
    - device: saltDev
    - fstype: 9p
    - opts: _netdev,trans=virtio,version=9p2000.L
    - require:
      - file: /opt/so/saltstack/default
      - mount: saltdev_fstab
      - cmd: load_9p_modules
