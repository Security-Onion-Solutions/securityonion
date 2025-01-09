#!/bin/bash

#raid3.sh is a refinement of raid2.sh. raid2.sh was used to create the raid in testing
#More detailed logging
#More thorough RAID array cleanup
#Better organized cleanup procedures
#Simplified device wiping using more modern tools (sgdisk instead of dd)
#More robust handling of existing MD arrays
#The core RAID creation and mounting functionality remains the same between both scripts, but the second version has improved error handling and cleanup procedures.

# Exit on any error
set -e

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log "Error: Please run as root"
        exit 1
    fi
}

# Function to perform thorough device cleanup
ensure_devices_free() {
    local device=$1
    
    log "Performing thorough cleanup of device $device"
    
    # Kill any processes using the device
    fuser -k "${device}"* 2>/dev/null || true
    
    # Force unmount any partitions
    for part in "${device}"*; do
        if mount | grep -q "$part"; then
            umount -f "$part" 2>/dev/null || true
        fi
    done
    
    # Stop any MD arrays using this device
    for md in $(ls /dev/md* 2>/dev/null || true); do
        if mdadm --detail "$md" 2>/dev/null | grep -q "$device"; then
            log "Stopping MD array $md"
            mdadm --stop "$md" 2>/dev/null || true
        fi
    done
    
    # Thorough RAID cleanup
    log "Cleaning RAID metadata from $device"
    mdadm --zero-superblock "$device" 2>/dev/null || true
    if [ -e "${device}p1" ]; then
        mdadm --zero-superblock "${device}p1" 2>/dev/null || true
    fi
    
    # Remove LVM PV if exists
    pvremove -ff -y "$device" 2>/dev/null || true
    
    # Clear all signatures
    log "Wiping all signatures from $device"
    wipefs -a "$device" 2>/dev/null || true
    
    # Clear partition table
    log "Clearing partition table on $device"
    sgdisk -Z "$device" 2>/dev/null || true
    
    # Force kernel to reread
    log "Forcing kernel to reread partition table"
    partprobe "$device" 2>/dev/null || true
    sleep 2
}

# Function to check if RAID is already set up
check_existing_raid() {
    # Clear existing mdadm configuration first
    log "Initializing clean mdadm configuration"
    echo "DEVICE partitions" > /etc/mdadm.conf
    
    if [ -e "/dev/md0" ]; then
        if mdadm --detail /dev/md0 &>/dev/null; then
            local raid_state=$(mdadm --detail /dev/md0 | grep "State" | awk '{print $3}')
            local mount_point="/nsm"
            
            log "Found existing RAID array /dev/md0 (State: $raid_state)"
            
            if mountpoint -q "$mount_point"; then
                log "RAID is already mounted at $mount_point"
                log "Current RAID details:"
                mdadm --detail /dev/md0
                
                # Check if resyncing
                if grep -q "resync" /proc/mdstat; then
                    log "RAID is currently resyncing:"
                    grep resync /proc/mdstat
                    log "You can monitor progress with: watch -n 60 cat /proc/mdstat"
                else
                    log "RAID is fully synced and operational"
                fi
                
                # Show disk usage
                log "Current disk usage:"
                df -h "$mount_point"
                
                exit 0
            fi
        fi
    fi
    
    # Check if any MD arrays exist and try to clean them up
    if [ -f /proc/mdstat ]; then
        log "Checking for existing MD arrays"
        if grep -q "md" /proc/mdstat; then
            log "Found existing MD arrays, attempting cleanup"
            for md in $(awk '/md/{print $1}' /proc/mdstat); do
                log "Stopping array $md"
                mdadm --stop "/dev/$md" 2>/dev/null || true
            done
        fi
    fi
    
    # Check if any of the target devices are in use
    for device in "/dev/nvme0n1" "/dev/nvme1n1"; do
        if lsblk -o NAME,MOUNTPOINT "$device" | grep -q "nsm"; then
            log "Error: $device is already mounted at /nsm"
            exit 1
        fi
    done
}

# Main script
main() {
    log "Starting RAID setup script"
    
    # Check if running as root
    check_root
    
    # Check for existing RAID setup
    check_existing_raid
    
    # Clean and prepare devices
    for device in "/dev/nvme0n1" "/dev/nvme1n1"; do
        ensure_devices_free "$device"
        
        log "Creating new partition table on $device"
        sgdisk -Z "$device"
        sgdisk -o "$device"
        
        log "Creating RAID partition"
        sgdisk -n 1:0:0 -t 1:fd00 "$device"
        
        partprobe "$device"
        udevadm settle
        sleep 5
    done
    
    log "Final verification of partition availability"
    if ! [ -b "/dev/nvme0n1p1" ] || ! [ -b "/dev/nvme1n1p1" ]; then
        log "Error: Partitions not available after creation"
        exit 1
    fi
    
    log "Creating RAID array"
    mdadm --create /dev/md0 --level=1 --raid-devices=2 \
          --metadata=1.2 \
          /dev/nvme0n1p1 /dev/nvme1n1p1 \
          --force --run
    
    log "Creating XFS filesystem"
    mkfs.xfs -f /dev/md0
    
    log "Creating mount point"
    mkdir -p /nsm
    
    log "Updating fstab"
    sed -i '/\/dev\/md0/d' /etc/fstab
    echo "/dev/md0  /nsm  xfs  defaults,nofail  0  0" >> /etc/fstab
    
    log "Reloading systemd daemon"
    systemctl daemon-reload
    
    log "Mounting filesystem"
    mount -a
    
    log "Saving RAID configuration"
    mdadm --detail --scan > /etc/mdadm.conf
    
    log "RAID setup complete"
    log "RAID array details:"
    mdadm --detail /dev/md0
    
    if grep -q "resync" /proc/mdstat; then
        log "RAID is currently resyncing. You can monitor progress with:"
        log "watch -n 60 cat /proc/mdstat"
    fi
}

# Run main function
main "$@"
