# quick script to create raid
# this is an example of the base functions
parted -s /dev/nvme0n1 rm 1
parted -s /dev/nvme0n1 mklabel gpt
parted -s /dev/nvme0n1 mkpart primary xfs 0% 100%
parted -s /dev/nvme0n1 set 1 raid on
parted -s /dev/nvme1n1 rm 1
parted -s /dev/nvme1n1 mklabel gpt
parted -s /dev/nvme1n1 mkpart primary xfs 0% 100%
parted -s /dev/nvme1n1 set 1 raid on
yes | mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/nvme0n1p1 /dev/nvme1n1p1

mkfs -t xfs -f /dev/md0
echo "Create NSM mount point"
mkdir -p /nsm
echo "Add mount to fstab"
echo "/dev/md0  /nsm  xfs defaults,nofail  0 0" >> /etc/fstab
echo "Mounting /nsm"
mount -a
mdadm --detail --scan --verbose >> /etc/mdadm.conf
