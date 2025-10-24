#!/opt/saltstack/salt/bin/python3

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
#
# Note: Per the Elastic License 2.0, the second limitation states:
#
#   "You may not move, change, disable, or circumvent the license key functionality
#    in the software, and you may not remove or obscure any functionality in the
#    software that is protected by the license key."

"""
Salt execution module for hypervisor operations.

This module provides functions for managing hypervisor configurations,
including VM file management.
"""

import json
import logging
import os

log = logging.getLogger(__name__)

__virtualname__ = 'hypervisor'


def __virtual__():
    """
    Only load this module if we're on a system that can manage hypervisors.
    """
    return __virtualname__


def remove_vm_from_vms_file(vms_file_path, vm_hostname, vm_role):
    """
    Remove a VM entry from the hypervisorVMs file.
    
    Args:
        vms_file_path (str): Path to the hypervisorVMs file
        vm_hostname (str): Hostname of the VM to remove (without role suffix)
        vm_role (str): Role of the VM
        
    Returns:
        dict: Result dictionary with success status and message
        
    CLI Example:
        salt '*' hypervisor.remove_vm_from_vms_file /opt/so/saltstack/local/salt/hypervisor/hosts/hypervisor1VMs node1 nsm
    """
    try:
        # Check if file exists
        if not os.path.exists(vms_file_path):
            msg = f"VMs file not found: {vms_file_path}"
            log.error(msg)
            return {'result': False, 'comment': msg}
        
        # Read current VMs
        with open(vms_file_path, 'r') as f:
            content = f.read().strip()
            vms = json.loads(content) if content else []
        
        # Find and remove the VM entry
        original_count = len(vms)
        vms = [vm for vm in vms if not (vm.get('hostname') == vm_hostname and vm.get('role') == vm_role)]
        
        if len(vms) < original_count:
            # VM was found and removed, write back to file
            with open(vms_file_path, 'w') as f:
                json.dump(vms, f, indent=2)
            
            # Set socore:socore ownership (939:939)
            os.chown(vms_file_path, 939, 939)
            
            msg = f"Removed VM {vm_hostname}_{vm_role} from {vms_file_path}"
            log.info(msg)
            return {'result': True, 'comment': msg}
        else:
            msg = f"VM {vm_hostname}_{vm_role} not found in {vms_file_path}"
            log.warning(msg)
            return {'result': False, 'comment': msg}
            
    except json.JSONDecodeError as e:
        msg = f"Failed to parse JSON in {vms_file_path}: {str(e)}"
        log.error(msg)
        return {'result': False, 'comment': msg}
    except Exception as e:
        msg = f"Failed to remove VM {vm_hostname}_{vm_role} from {vms_file_path}: {str(e)}"
        log.error(msg)
        return {'result': False, 'comment': msg}
