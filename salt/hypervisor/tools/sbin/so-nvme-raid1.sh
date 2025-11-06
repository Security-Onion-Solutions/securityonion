#!/bin/bash

#################################################################
# RAID-1 Setup Script for NVMe Drives
#################################################################
# 
# DESCRIPTION:
# This script automatically sets up a RAID-1 (mirrored) array using two NVMe drives
# (/dev/nvme0n1 and /dev/nvme1n1) and mounts it at /nsm with XFS filesystem.
#
# FUNCTIONALITY:
# - Detects and reports existing RAID configurations
# - Thoroughly cleans target drives of any existing data/configurations
# - Creates GPT partition tables with RAID-type partitions
# - Establishes RAID-1 array (${RAID_DEVICE}) for data redundancy
# - Formats the array with XFS filesystem for performance
# - Automatically mounts at /nsm and configures for boot persistence
# - Provides monitoring information for resync operations
#
# SAFETY FEATURES:
# - Requires root privileges
# - Exits gracefully if RAID already exists and is mounted
# - Performs comprehensive cleanup to avoid conflicts
# - Forces partition table updates and waits for system recognition
#
# PREREQUISITES:
# - Two NVMe drives: /dev/nvme0n1 and /dev/nvme1n1
# - Root access
# - mdadm, sgdisk, and standard Linux utilities
#
# WARNING: This script will DESTROY all data on the target drives!
#
# USAGE: 
#   sudo ./so-nvme-raid1.sh              # Normal operation
#   sudo ./so-nvme-raid1.sh --force-cleanup  # Force cleanup of existing RAID
#
#################################################################

# Exit on any error
set -e

# Configuration variables
RAID_ARRAY_NAME="md0"
RAID_DEVICE="/dev/${RAID_ARRAY_NAME}"
MOUNT_POINT="/nsm"
FORCE_CLEANUP=false

# Parse command line arguments
for arg in "$@"; do
    case $arg in
        --force-cleanup)
            FORCE_CLEANUP=true
            shift
            ;;
        *)
            ;;
    esac
done

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

# Function to force cleanup all RAID components
force_cleanup_raid() {
    log "=== FORCE CLEANUP MODE ==="
    log "This will destroy all RAID configurations and data on target drives!"
    
    # Stop all MD arrays
    log "Stopping all MD arrays"
    mdadm --stop --scan 2>/dev/null || true
    
    # Wait for arrays to stop
    sleep 2
    
    # Remove any running md devices
    for md in /dev/md*; do
        if [ -b "$md" ]; then
            log "Stopping $md"
            mdadm --stop "$md" 2>/dev/null || true
        fi
    done
    
    # Force cleanup both NVMe drives
    for device in "/dev/nvme0n1" "/dev/nvme1n1"; do
        log "Force cleaning $device"
        
        # Kill any processes using the device
        fuser -k "${device}"* 2>/dev/null || true
        
        # Unmount any mounted partitions
        for part in "${device}"*; do
            if [ -b "$part" ]; then
                umount -f "$part" 2>/dev/null || true
            fi
        done
        
        # Force zero RAID superblocks on partitions
        for part in "${device}"p*; do
            if [ -b "$part" ]; then
                log "Zeroing RAID superblock on $part"
                mdadm --zero-superblock --force "$part" 2>/dev/null || true
            fi
        done
        
        # Zero superblock on the device itself
        log "Zeroing RAID superblock on $device"
        mdadm --zero-superblock --force "$device" 2>/dev/null || true
        
        # Remove LVM physical volumes
        pvremove -ff -y "$device" 2>/dev/null || true
        
        # Wipe all filesystem and partition signatures
        log "Wiping all signatures from $device"
        wipefs -af "$device" 2>/dev/null || true
        
        # Overwrite the beginning of the drive (partition table area)
        log "Clearing partition table on $device"
        dd if=/dev/zero of="$device" bs=1M count=10 2>/dev/null || true
        
        # Clear the end of the drive (backup partition table area)
        local device_size=$(blockdev --getsz "$device" 2>/dev/null || echo "0")
        if [ "$device_size" -gt 0 ]; then
            dd if=/dev/zero of="$device" bs=512 seek=$(( device_size - 2048 )) count=2048 2>/dev/null || true
        fi
        
        # Force kernel to re-read partition table
        blockdev --rereadpt "$device" 2>/dev/null || true
        partprobe -s "$device" 2>/dev/null || true
    done
    
    # Clear mdadm configuration
    log "Clearing mdadm configuration"
    echo "DEVICE partitions" > /etc/mdadm.conf
    
    # Remove any fstab entries for the RAID device or mount point
    log "Cleaning fstab entries"
    sed -i "\|${RAID_DEVICE}|d" /etc/fstab
    sed -i "\|${MOUNT_POINT}|d" /etc/fstab
    
    # Wait for system to settle
    udevadm settle
    sleep 5
    
    log "Force cleanup complete!"
    log "Proceeding with RAID setup..."
}

# Function to find MD arrays using specific devices
find_md_arrays_using_devices() {
    local target_devices=("$@")
    local found_arrays=()
    
    # Parse /proc/mdstat to find arrays using our target devices
    if [ -f "/proc/mdstat" ]; then
        while IFS= read -r line; do
            if [[ $line =~ ^(md[0-9]+) ]]; then
                local array_name="${BASH_REMATCH[1]}"
                local array_path="/dev/$array_name"
                
                # Check if this array uses any of our target devices
                for device in "${target_devices[@]}"; do
                    if echo "$line" | grep -q "${device##*/}"; then
                        found_arrays+=("$array_path")
                        break
                    fi
                done
            fi
        done < /proc/mdstat
    fi
    
    printf '%s\n' "${found_arrays[@]}"
}

# Function to check if RAID is already set up
check_existing_raid() {
    local target_devices=("/dev/nvme0n1p1" "/dev/nvme1n1p1")
    local found_arrays=($(find_md_arrays_using_devices "${target_devices[@]}"))
    
    # Check if we found any arrays using our target devices
    if [ ${#found_arrays[@]} -gt 0 ]; then
        for array_path in "${found_arrays[@]}"; do
            if mdadm --detail "$array_path" &>/dev/null; then
                local raid_state=$(mdadm --detail "$array_path" | grep "State" | awk '{print $3}')
                local mount_point="/nsm"
                
                log "Found existing RAID array $array_path (State: $raid_state)"
                
                # Check what's currently mounted at /nsm
                local current_mount=$(findmnt -n -o SOURCE "$mount_point" 2>/dev/null || echo "")
                
                if [ -n "$current_mount" ]; then
                    if [ "$current_mount" = "$array_path" ]; then
                        log "RAID array $array_path is already correctly mounted at $mount_point"
                        log "Current RAID details:"
                        mdadm --detail "$array_path"
                        
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
                    else
                        log "Found $mount_point mounted on $current_mount, but RAID array $array_path exists"
                        log "Will unmount current filesystem and remount on RAID array"
                        
                        # Unmount current filesystem
                        log "Unmounting $mount_point"
                        umount "$mount_point"
                        
                        # Remove old fstab entry
                        log "Removing old fstab entry for $current_mount"
                        sed -i "\|$current_mount|d" /etc/fstab
                        
                        # Mount the RAID array
                        log "Mounting RAID array $array_path at $mount_point"
                        mount "$array_path" "$mount_point"
                        
                        # Update fstab
                        log "Updating fstab for RAID array"
                        sed -i "\|${array_path}|d" /etc/fstab
                        echo "${array_path}  ${mount_point}  xfs  defaults,nofail  0  0" >> /etc/fstab
                        
                        log "RAID array is now mounted at $mount_point"
                        log "Current RAID details:"
                        mdadm --detail "$array_path"
                        
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
                else
                    # /nsm not mounted, mount the RAID array
                    log "Mounting RAID array $array_path at $mount_point"
                    mount "$array_path" "$mount_point"
                    
                    # Update fstab
                    log "Updating fstab for RAID array"
                    sed -i "\|${array_path}|d" /etc/fstab
                    echo "${array_path}  ${mount_point}  xfs  defaults,nofail  0  0" >> /etc/fstab
                    
                    log "RAID array is now mounted at $mount_point"
                    log "Current RAID details:"
                    mdadm --detail "$array_path"
                    
                    # Show disk usage
                    log "Current disk usage:"
                    df -h "$mount_point"
                    
                    exit 0
                fi
            fi
        done
    fi
    
    # Check if any of the target devices are in use
    for device in "/dev/nvme0n1" "/dev/nvme1n1"; do        
        if mdadm --examine "$device" &>/dev/null || mdadm --examine "${device}p1" &>/dev/null; then
            # Find the actual array name for this device
            local device_arrays=($(find_md_arrays_using_devices "${device}p1"))
            local array_name=""
            
            if [ ${#device_arrays[@]} -gt 0 ]; then
                array_name="${device_arrays[0]}"
            else
                # Fallback: try to find array name from /proc/mdstat
                local partition_name="${device##*/}p1"
                array_name=$(grep -l "$partition_name" /proc/mdstat 2>/dev/null | head -1)
                if [ -n "$array_name" ]; then
                    array_name=$(grep "^md[0-9]" /proc/mdstat | grep "$partition_name" | awk '{print "/dev/" $1}' | head -1)
                fi
                # Final fallback
                if [ -z "$array_name" ]; then
                    array_name="$RAID_DEVICE"
                fi
            fi
            
            log "Error: $device appears to be part of an existing RAID array"
            log "Old RAID metadata detected but array is not running."
            log ""
            log "To fix this, run the script with --force-cleanup:"
            log "  sudo $0 --force-cleanup"
            log ""
            log "Or manually clean up with:"
            log "1. Stop any arrays: mdadm --stop --scan"
            log "2. Zero superblocks: mdadm --zero-superblock --force ${device}p1"
            log "3. Wipe signatures: wipefs -af $device"
            exit 1
        fi
    done
}

# Function to ensure devices are not in use
ensure_devices_free() {
    local device=$1
    
    log "Cleaning up device $device"
    
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
            mdadm --stop "$md" 2>/dev/null || true
        fi
    done
    
    # Clear MD superblock
    mdadm --zero-superblock --force "${device}"* 2>/dev/null || true
    
    # Remove LVM PV if exists
    pvremove -ff -y "$device" 2>/dev/null || true
    
    # Clear all signatures
    wipefs -af "$device" 2>/dev/null || true
    
    # Delete partition table
    dd if=/dev/zero of="$device" bs=512 count=2048 2>/dev/null || true
    dd if=/dev/zero of="$device" bs=512 seek=$(( $(blockdev --getsz "$device") - 2048 )) count=2048 2>/dev/null || true
    
    # Force kernel to reread
    blockdev --rereadpt "$device" 2>/dev/null || true
    partprobe -s "$device" 2>/dev/null || true
    sleep 2
}

# Main script
main() {
    log "Starting RAID setup script"
    
    # Check if running as root
    check_root
    
    # If force cleanup flag is set, do aggressive cleanup first
    if [ "$FORCE_CLEANUP" = true ]; then
        force_cleanup_raid
    fi
    
    # Check for existing RAID setup
    check_existing_raid
    
    # Clean up any existing MD arrays
    log "Cleaning up existing MD arrays"
    mdadm --stop --scan 2>/dev/null || true
    
    # Clear mdadm configuration
    log "Clearing mdadm configuration"
    echo "DEVICE partitions" > /etc/mdadm.conf
    
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
    mdadm --create "$RAID_DEVICE" --level=1 --raid-devices=2 \
          --metadata=1.2 \
          /dev/nvme0n1p1 /dev/nvme1n1p1 \
          --force --run
    
    log "Creating XFS filesystem"
    mkfs.xfs -f "$RAID_DEVICE"
    
    log "Creating mount point"
    mkdir -p /nsm
    
    log "Updating fstab"
    sed -i "\|${RAID_DEVICE}|d" /etc/fstab
    echo "${RAID_DEVICE}  ${MOUNT_POINT}  xfs  defaults,nofail  0  0" >> /etc/fstab
    
    log "Reloading systemd daemon"
    systemctl daemon-reload
    
    log "Mounting filesystem"
    mount -a
    
    log "Saving RAID configuration"
    mdadm --detail --scan > /etc/mdadm.conf
    
    log "RAID setup complete"
    log "RAID array details:"
    mdadm --detail "$RAID_DEVICE"
    
    if grep -q "resync" /proc/mdstat; then
        log "RAID is currently resyncing. You can monitor progress with:"
        log "watch -n 60 cat /proc/mdstat"
    fi
}

# Run main function
main "$@"
