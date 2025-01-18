#!py

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
Salt module for managing QCOW2 image configurations and VM hardware settings. This module provides functions
for modifying network configurations within QCOW2 images and adjusting virtual machine hardware settings.
It serves as a Salt interface to the so-qcow2-modify-network and so-kvm-modify-hardware scripts.

The module offers two main capabilities:
1. Network Configuration: Modify network settings (DHCP/static IP) within QCOW2 images
2. Hardware Configuration: Adjust VM hardware settings (CPU, memory, PCI passthrough)

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

def modify_network_config(image, interface, mode, ip4=None, gw4=None, dns4=None, search4=None):
    '''
    Usage:
        salt '*' qcow2.modify_network_config image=<path> interface=<iface> mode=<mode> [ip4=<addr>] [gw4=<addr>] [dns4=<servers>] [search4=<domain>]

    Options:
        image
            Path to the QCOW2 image file that will be modified
        interface
            Network interface name to configure (e.g., 'eth0')
        mode
            Network configuration mode, either 'dhcp4' or 'static4'
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
            salt '*' qcow2.modify_network_config image='/nsm/libvirt/images/sool9/sool9.qcow2' interface='eth0' mode='dhcp4'
            ```
            This configures eth0 to use DHCP for IP assignment

        2. **Configure Static IP:**
            ```bash
            salt '*' qcow2.modify_network_config image='/nsm/libvirt/images/sool9/sool9.qcow2' interface='eth0' mode='static4' ip4='192.168.1.10/24' gw4='192.168.1.1' dns4='192.168.1.1,8.8.8.8' search4='example.local'
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

    cmd = ['/usr/sbin/so-qcow2-modify-network', '-I', image, '-i', interface]

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
        salt '*' qcow2.modify_hardware_config vm_name=<name> [cpu=<count>] [memory=<size>] [pci=<id>] [start=<bool>]

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
            PCI hardware ID to passthrough to the VM (e.g., '0000:00:1f.2')
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
            salt '*' qcow2.modify_hardware_config vm_name='sensor1' pci='0000:00:1f.2' start=True
            ```
            This configures PCI passthrough and starts the VM

        3. **Complete Hardware Configuration:**
            ```bash
            salt '*' qcow2.modify_hardware_config vm_name='sensor1' cpu=8 memory=16384 pci='0000:00:1f.2' start=True
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
        cmd.extend(['-p', pci])
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
