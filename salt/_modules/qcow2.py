#!py

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
Salt module for managing QCOW2 image configurations and VM hardware settings. This module provides functions
for modifying network configurations within QCOW2 images, adjusting virtual machine hardware settings, and
creating virtual storage volumes. It serves as a Salt interface to the so-qcow2-modify-network,
so-kvm-modify-hardware, and so-kvm-create-volume scripts.

The module offers three main capabilities:
1. Network Configuration: Modify network settings (DHCP/static IP) within QCOW2 images
2. Hardware Configuration: Adjust VM hardware settings (CPU, memory, PCI passthrough)
3. Volume Management: Create and attach virtual storage volumes for NSM data

This module is intended to work with Security Onion's virtualization infrastructure and is typically
used in conjunction with salt-cloud for VM provisioning and management.
"""

import logging
import subprocess
import shlex

log = logging.getLogger(__name__)

__virtualname__ = 'qcow2'

def __virtual__():
    return __virtualname__

def modify_network_config(image, interface, mode, vm_name, ip4=None, gw4=None, dns4=None, search4=None):
    '''
    Usage:
        salt '*' qcow2.modify_network_config image=<path> interface=<iface> mode=<mode> vm_name=<name> [ip4=<addr>] [gw4=<addr>] [dns4=<servers>] [search4=<domain>]

    Options:
        image
            Path to the QCOW2 image file that will be modified
        interface
            Network interface name to configure (e.g., 'enp1s0')
        mode
            Network configuration mode, either 'dhcp4' or 'static4'
        vm_name
            Full name of the VM (hostname_role)
        ip4
            IPv4 address with CIDR notation (e.g., '192.168.1.10/24')
            Required when mode='static4'
        gw4
            IPv4 gateway address (e.g., '192.168.1.1')
            Required when mode='static4'
        dns4
            Comma-separated list of IPv4 DNS servers (e.g., '8.8.8.8,8.8.4.4')
            Optional for both DHCP and static configurations
        search4
            DNS search domain for IPv4 (e.g., 'example.local')
            Optional for both DHCP and static configurations

    Examples:
        1. **Configure DHCP:**
            ```bash
            salt '*' qcow2.modify_network_config image='/nsm/libvirt/images/sool9/sool9.qcow2' interface='enp1s0' mode='dhcp4'
            ```
            This configures enp1s0 to use DHCP for IP assignment

        2. **Configure Static IP:**
            ```bash
            salt '*' qcow2.modify_network_config image='/nsm/libvirt/images/sool9/sool9.qcow2' interface='enp1s0' mode='static4' ip4='192.168.1.10/24' gw4='192.168.1.1' dns4='192.168.1.1,8.8.8.8' search4='example.local'
            ```
            This sets a static IP configuration with DNS servers and search domain

    Notes:
        - The QCOW2 image must be accessible and writable by the salt minion
        - The image should not be in use by a running VM when modified
        - Network changes take effect on next VM boot
        - Requires so-qcow2-modify-network script to be installed

    Description:
        This function modifies network configuration within a QCOW2 image file by executing
        the so-qcow2-modify-network script. It supports both DHCP and static IPv4 configuration.
        The script mounts the image, modifies the network configuration files, and unmounts
        safely. All operations are logged for troubleshooting purposes.

    Exit Codes:
        0: Success
        1: Invalid parameters or configuration
        2: Image access or mounting error
        3: Network configuration error
        4: System command error
        255: Unexpected error

    Logging:
        - All operations are logged to the salt minion log
        - Log entries are prefixed with 'qcow2 module:'
        - Error conditions include detailed error messages and stack traces
        - Success/failure status is logged for verification
    '''

    cmd = ['/usr/sbin/so-qcow2-modify-network', '-I', image, '-i', interface, '-n', vm_name]

    if mode.lower() == 'dhcp4':
        cmd.append('--dhcp4')
    elif mode.lower() == 'static4':
        cmd.append('--static4')
        if not ip4 or not gw4:
            raise ValueError('Both ip4 and gw4 are required for static configuration.')
        cmd.extend(['--ip4', ip4, '--gw4', gw4])
        if dns4:
            cmd.extend(['--dns4', dns4])
        if search4:
            cmd.extend(['--search4', search4])
    else:
        raise ValueError("Invalid mode '{}'. Expected 'dhcp4' or 'static4'.".format(mode))

    log.info('qcow2 module: Executing command: {}'.format(' '.join(shlex.quote(arg) for arg in cmd)))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        ret = {
            'retcode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
        if result.returncode != 0:
            log.error('qcow2 module: Script execution failed with return code {}: {}'.format(result.returncode, result.stderr))
        else:
            log.info('qcow2 module: Script executed successfully.')
        return ret
    except Exception as e:
        log.error('qcow2 module: An error occurred while executing the script: {}'.format(e))
        raise

def modify_hardware_config(vm_name, cpu=None, memory=None, pci=None, start=False):
    '''
    Usage:
        salt '*' qcow2.modify_hardware_config vm_name=<name> [cpu=<count>] [memory=<size>] [pci=<id>] [pci=<id>] [start=<bool>]

    Options:
        vm_name
            Name of the virtual machine to modify
        cpu
            Number of virtual CPUs to assign (positive integer)
            Optional - VM's current CPU count retained if not specified
        memory
            Amount of memory to assign in MiB (positive integer)
            Optional - VM's current memory size retained if not specified
        pci
            PCI hardware ID(s) to passthrough to the VM (e.g., '0000:c7:00.0')
            Can be specified multiple times for multiple devices
            Optional - no PCI passthrough if not specified
        start
            Boolean flag to start the VM after modification
            Optional - defaults to False

    Examples:
        1. **Modify CPU and Memory:**
            ```bash
            salt '*' qcow2.modify_hardware_config vm_name='sensor1' cpu=4 memory=8192
            ```
            This assigns 4 CPUs and 8GB memory to the VM

        2. **Enable PCI Passthrough:**
            ```bash
            salt '*' qcow2.modify_hardware_config vm_name='sensor1' pci='0000:c7:00.0' pci='0000:c4:00.0' start=True
            ```
            This configures PCI passthrough and starts the VM

        3. **Complete Hardware Configuration:**
            ```bash
            salt '*' qcow2.modify_hardware_config vm_name='sensor1' cpu=8 memory=16384 pci='0000:c7:00.0' start=True
            ```
            This sets CPU, memory, PCI passthrough, and starts the VM

    Notes:
        - VM must be stopped before modification unless only the start flag is set
        - Memory is specified in MiB (1024 = 1GB)
        - PCI devices must be available and not in use by the host
        - CPU count should align with host capabilities
        - Requires so-kvm-modify-hardware script to be installed

    Description:
        This function modifies the hardware configuration of a KVM virtual machine using
        the so-kvm-modify-hardware script. It can adjust CPU count, memory allocation,
        and PCI device passthrough. Changes are applied to the VM's libvirt configuration.
        The VM can optionally be started after modifications are complete.

    Exit Codes:
        0: Success
        1: Invalid parameters
        2: VM state error (running when should be stopped)
        3: Hardware configuration error
        4: System command error
        255: Unexpected error

    Logging:
        - All operations are logged to the salt minion log
        - Log entries are prefixed with 'qcow2 module:'
        - Hardware configuration changes are logged
        - Errors include detailed messages and stack traces
        - Final status of modification is logged
    '''

    cmd = ['/usr/sbin/so-kvm-modify-hardware', '-v', vm_name]

    if cpu is not None:
        if isinstance(cpu, int) and cpu > 0:
            cmd.extend(['-c', str(cpu)])
        else:
            raise ValueError('cpu must be a positive integer.')
    if memory is not None:
        if isinstance(memory, int) and memory > 0:
            cmd.extend(['-m', str(memory)])
        else:
            raise ValueError('memory must be a positive integer.')
    if pci:
        # Handle PCI IDs (can be a single device or comma-separated list)
        if isinstance(pci, str):
            devices = [dev.strip() for dev in pci.split(',') if dev.strip()]
        elif isinstance(pci, list):
            devices = pci
        else:
            devices = [pci]

        # Add each device with its own -p flag
        for device in devices:
            cmd.extend(['-p', str(device)])
    if start:
        cmd.append('-s')

    log.info('qcow2 module: Executing command: {}'.format(' '.join(shlex.quote(arg) for arg in cmd)))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        ret = {
            'retcode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
        if result.returncode != 0:
            log.error('qcow2 module: Script execution failed with return code {}: {}'.format(result.returncode, result.stderr))
        else:
            log.info('qcow2 module: Script executed successfully.')
        return ret
    except Exception as e:
        log.error('qcow2 module: An error occurred while executing the script: {}'.format(e))
        raise

def create_volume_config(vm_name, size_gb, start=False):
    '''
    Usage:
        salt '*' qcow2.create_volume_config vm_name=<name> size_gb=<size> [start=<bool>]

    Options:
        vm_name
            Name of the virtual machine to attach the volume to
        size_gb
            Volume size in GB (positive integer)
            This determines the capacity of the virtual storage volume
        start
            Boolean flag to start the VM after volume creation
            Optional - defaults to False

    Examples:
        1. **Create 500GB Volume:**
            ```bash
            salt '*' qcow2.create_volume_config vm_name='sensor1_sensor' size_gb=500
            ```
            This creates a 500GB virtual volume for NSM storage

        2. **Create 1TB Volume and Start VM:**
            ```bash
            salt '*' qcow2.create_volume_config vm_name='sensor1_sensor' size_gb=1000 start=True
            ```
            This creates a 1TB volume and starts the VM after attachment

    Notes:
        - VM must be stopped before volume creation
        - Volume is created as a qcow2 image and attached to the VM
        - This is an alternative to disk passthrough via modify_hardware_config
        - Volume is automatically attached to the VM's libvirt configuration
        - Requires so-kvm-create-volume script to be installed
        - Volume files are stored in the hypervisor's VM storage directory

    Description:
        This function creates and attaches a virtual storage volume to a KVM virtual machine
        using the so-kvm-create-volume script. It creates a qcow2 disk image of the specified
        size and attaches it to the VM for NSM (Network Security Monitoring) storage purposes.
        This provides an alternative to physical disk passthrough, allowing flexible storage
        allocation without requiring dedicated hardware. The VM can optionally be started
        after the volume is successfully created and attached.

    Exit Codes:
        0: Success
        1: Invalid parameters
        2: VM state error (running when should be stopped)
        3: Volume creation error
        4: System command error
        255: Unexpected error

    Logging:
        - All operations are logged to the salt minion log
        - Log entries are prefixed with 'qcow2 module:'
        - Volume creation and attachment operations are logged
        - Errors include detailed messages and stack traces
        - Final status of volume creation is logged
    '''

    # Validate size_gb parameter
    if not isinstance(size_gb, int) or size_gb <= 0:
        raise ValueError('size_gb must be a positive integer.')

    cmd = ['/usr/sbin/so-kvm-create-volume', '-v', vm_name, '-s', str(size_gb)]

    if start:
        cmd.append('-S')

    log.info('qcow2 module: Executing command: {}'.format(' '.join(shlex.quote(arg) for arg in cmd)))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        ret = {
            'retcode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
        if result.returncode != 0:
            log.error('qcow2 module: Script execution failed with return code {}: {}'.format(result.returncode, result.stderr))
        else:
            log.info('qcow2 module: Script executed successfully.')
        return ret
    except Exception as e:
        log.error('qcow2 module: An error occurred while executing the script: {}'.format(e))
        raise
