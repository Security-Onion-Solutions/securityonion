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
Salt Engine for Virtual Machine Power Management

This engine manages power control actions for virtual machines in Security Onion's
virtualization infrastructure. It monitors VM configurations for power control requests
and executes the appropriate virt module actions.

Usage:
    engines:
      - virtual_power_manager:
          interval: 60
          base_path: /opt/so/saltstack/local/salt/hypervisor/hosts

Options:
    interval: Time in seconds between engine runs (managed by salt-master, default: 60)
    base_path: Base directory containing hypervisor configurations (default: /opt/so/saltstack/local/salt/hypervisor/hosts)

Configuration Files:
    <hypervisorHostname>VMs: JSON file containing VM configurations
        - Located at <base_path>/<hypervisorHostname>VMs
        - Contains array of VM configurations
        - Power control requests are specified with the "powercontrol" key
        - Valid values for "powercontrol": "Reboot", "Reset", "Shutdown", "Start", "Stop"

Examples:
    1. Basic Configuration:
        engines:
          - virtual_power_manager: {}
        
        Uses default settings to process power control requests every 60 seconds.

    2. Custom Interval:
        engines:
          - virtual_power_manager:
              interval: 120
        
        Processes power control requests every 120 seconds.

Power Control Actions:
    - Reboot: Gracefully reboot the VM (virt.reboot)
    - Reset: Force reset the VM (virt.reset)
    - Shutdown: Gracefully shut down the VM (virt.shutdown)
    - Start: Start the VM (virt.start)
    - Stop: Force stop the VM (virt.stop)

Notes:
    - File locking is used to prevent race conditions when multiple processes access the VMs file
    - The "powercontrol" key is removed from the VM configuration after successful execution
    - Comprehensive logging for troubleshooting
    - No continuous loop (salt-master handles scheduling)
    - File locking is only applied when a powercontrol key is detected, not on every run

Description:
   The engine operates in the following phases:

   1. Configuration Processing
      - Reads VMs file for each hypervisor without locking
      - Identifies VMs with "powercontrol" key
      - If powercontrol key is found, acquires lock and reads file again

   2. Power Control Execution
      - Maps "powercontrol" value to virt module function
      - Executes appropriate virt module command
      - Removes "powercontrol" key after successful execution

   3. File Locking
      - Acquires lock only when a powercontrol key is detected
      - Releases lock after modifications
      - Handles lock acquisition failures

Logging:
    Log files are written to /opt/so/log/salt/master
    Comprehensive logging includes:
    - Power control action details
    - Command execution results
    - Error conditions with full context
    - File locking operations
"""

import os
import glob
import json
import logging
import fcntl
import salt.client
from typing import Dict, List, Optional, Any, Tuple

# Configure logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# Constants
DEFAULT_INTERVAL = 60
DEFAULT_BASE_PATH = '/opt/so/saltstack/local/salt/hypervisor/hosts'
VALID_POWER_ACTIONS = {'Reboot', 'Reset', 'Shutdown', 'Start', 'Stop'}

class FileLock:
    """
    Context manager for file locking.
    
    This class provides a context manager for file locking using fcntl.
    It acquires an exclusive lock on the file when entering the context
    and releases the lock when exiting.
    
    Example:
        with FileLock(file_path):
            # Read and modify file
            # Lock is automatically released when exiting the context
    """
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.lock_path = f"{file_path}.lock"
        self.lock_file = None
        
    def __enter__(self):
        try:
            # Open the lock file
            self.lock_file = open(self.lock_path, 'w')
            
            # Acquire exclusive lock
            fcntl.flock(self.lock_file, fcntl.LOCK_EX)
            log.debug("Acquired lock on %s", self.file_path)
            
            return self
            
        except Exception as e:
            log.error("Failed to acquire lock on %s: %s", self.file_path, str(e))
            if self.lock_file:
                self.lock_file.close()
            raise
            
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            # Release lock
            if self.lock_file:
                fcntl.flock(self.lock_file, fcntl.LOCK_UN)
                self.lock_file.close()
                log.debug("Released lock on %s", self.file_path)
                
            # Remove lock file
            if os.path.exists(self.lock_path):
                os.remove(self.lock_path)
                
        except Exception as e:
            log.error("Error releasing lock on %s: %s", self.file_path, str(e))

def read_json_file(file_path: str) -> Any:
    """
    Read and parse a JSON file.
    Returns an empty array if the file is empty.
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            if not content:
                return []
            return json.loads(content)
    except Exception as e:
        log.error("Failed to read JSON file %s: %s", file_path, str(e))
        raise

def write_json_file(file_path: str, data: Any) -> None:
    """Write data to a JSON file."""
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        log.error("Failed to write JSON file %s: %s", file_path, str(e))
        raise

def has_power_control_requests(nodes_config: List[Dict]) -> bool:
    """
    Check if any VM in the configuration has a powercontrol key.
    
    Args:
        nodes_config: List of VM configurations
        
    Returns:
        True if at least one VM has a powercontrol key, False otherwise
    """
    return any('powercontrol' in vm_config for vm_config in nodes_config)

def process_power_control(hypervisor: str, vm_config: dict) -> bool:
    """
    Process a power control request for a VM.
    
    Args:
        hypervisor: Name of the hypervisor
        vm_config: VM configuration dictionary
        
    Returns:
        True if the power control action was successful, False otherwise
    """
    try:
        # Get VM name and power control action
        vm_name = f"{vm_config['hostname']}_{vm_config['role']}"
        power_action = vm_config['powercontrol']
        
        # Validate power action
        if power_action not in VALID_POWER_ACTIONS:
            log.error("Invalid power control action: %s", power_action)
            return False
            
        # Map power action to virt module function
        virt_function = power_action.lower()
        
        # Execute power control action
        log.info("Executing %s on VM %s", power_action, vm_name)
        client = salt.client.LocalClient()
        result = client.cmd(
            f"{hypervisor}_*",
            f"virt.{virt_function}",
            [vm_name],
            expr_form="glob"
        )
        
        # Check result
        if result and any(success for success in result.values()):
            log.info("Successfully executed %s on VM %s", power_action, vm_name)
            return True
        else:
            log.error("Failed to execute %s on VM %s: %s", power_action, vm_name, result)
            return False
            
    except Exception as e:
        log.error("Error processing power control for VM %s: %s", vm_config.get('hostname', 'unknown'), str(e))
        return False

def process_hypervisor_power_requests(hypervisor_path: str) -> None:
    """
    Process power control requests for a single hypervisor.
    
    Args:
        hypervisor_path: Path to the hypervisor directory
    """
    try:
        # Get hypervisor name from path
        hypervisor = os.path.basename(hypervisor_path)
        
        # Read VMs file
        vms_file = os.path.join(os.path.dirname(hypervisor_path), f"{hypervisor}VMs")
        if not os.path.exists(vms_file):
            log.debug("No VMs file found at %s", vms_file)
            return
        
        # First, read the file without locking to check if any VM has a powercontrol key
        nodes_config = read_json_file(vms_file)
        if not nodes_config:
            log.debug("Empty VMs configuration in %s", vms_file)
            return
        
        # Check if any VM has a powercontrol key
        if not has_power_control_requests(nodes_config):
            log.debug("No power control requests found in %s", vms_file)
            return
        
        # If we found powercontrol keys, lock the file and process the requests
        with FileLock(vms_file):
            # Read the VMs file again with the lock to ensure we have the latest data
            nodes_config = read_json_file(vms_file)
            if not nodes_config:
                log.debug("Empty VMs configuration in %s (after lock)", vms_file)
                return
            
            # Track if any changes were made
            changes_made = False
            
            # Process each VM configuration
            for i, vm_config in enumerate(nodes_config):
                if 'powercontrol' in vm_config:
                    # Process power control request
                    log.info("Found power control request for VM %s_%s: %s", 
                             vm_config.get('hostname', 'unknown'), 
                             vm_config.get('role', 'unknown'),
                             vm_config['powercontrol'])
                    
                    success = process_power_control(hypervisor, vm_config)
                    if success:
                        # Remove powercontrol key
                        log.info("Power control action successful, removing powercontrol key")
                        del nodes_config[i]['powercontrol']
                        changes_made = True
            
            # Write updated configuration if changes were made
            if changes_made:
                log.info("Writing updated VM configuration to %s", vms_file)
                write_json_file(vms_file, nodes_config)
                
    except Exception as e:
        log.error("Failed to process hypervisor %s: %s", hypervisor_path, str(e))
        raise

def start(interval: int = DEFAULT_INTERVAL,
          base_path: str = DEFAULT_BASE_PATH) -> None:
    """
    Process virtual machine power control requests.
    
    This function processes power control requests for virtual machines
    by monitoring the <hypervisor>VMs files for the "powercontrol" key.
    
    Args:
        interval: Time in seconds between engine runs (managed by salt-master)
        base_path: Base path containing hypervisor configurations
    """
    log.debug("Starting virtual power manager engine")
    
    try:
        # Process each hypervisor directory
        for hypervisor_path in glob.glob(os.path.join(base_path, '*')):
            if os.path.isdir(hypervisor_path):
                process_hypervisor_power_requests(hypervisor_path)
                
        log.debug("Virtual power manager completed successfully")
                
    except Exception as e:
        log.error("Error in virtual power manager: %s", str(e))
