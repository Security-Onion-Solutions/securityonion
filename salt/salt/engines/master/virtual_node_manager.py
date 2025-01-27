#!/opt/saltstack/salt/bin/python3

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
Salt Engine for Virtual Node Management

This engine manages the automated provisioning of virtual machines in Security Onion's 
virtualization infrastructure. It monitors directories for VM creation requests and 
handles the entire provisioning process including hardware allocation.

Usage:
    engines:
      - virtual_node_manager:
          interval: 30
          base_path: /opt/so/saltstack/local/salt/hypervisor/hosts

Options:
    interval: Time in seconds between directory scans (default: 30)
    base_path: Base directory to monitor for VM requests (default: /opt/so/saltstack/local/salt/hypervisor/hosts)
    
    Memory values in VM configuration YAML files should be specified in GB. These values
    will automatically be converted to MiB when passed to so-salt-cloud.

Examples:
    1. Basic Configuration:
        engines:
          - virtual_node_manager: {}
        
        Uses default settings to monitor for VM requests.

    2. Custom Scan Interval:
        engines:
          - virtual_node_manager:
              interval: 60
        
        Scans for new requests every 60 seconds.

Notes:
    - Requires 'hvn' feature license
    - Monitors for files named: add_sensor, add_searchnode, add_idh, add_receiver, add_heavynode, add_fleet
    - Hardware allocation is tracked in hypervisor YAML files
    - Creates VM-specific hardware tracking files

Description:
    The engine operates in the following phases:

    1. License Validation
       - Verifies 'hvn' feature is licensed
       - Prevents operation if license is invalid

    2. File Monitoring
       - Scans configured directory for add_* files
       - Parses VM configuration from YAML
       - Validates configuration parameters

    3. Hardware Allocation
       - Reads hypervisor hardware inventory
       - Claims requested PCI devices
       - Updates hardware tracking
       - Creates VM hardware record

    4. VM Provisioning
       - Executes so-salt-cloud with configuration
       - Handles network setup
       - Configures hardware passthrough
       - Manages VM startup

Exit Codes:
    0: Success
    1: Invalid license
    2: Configuration error
    3: Hardware allocation failure
    4: VM provisioning failure

Logging:
    Log files are written to /opt/so/log/salt/engines/virtual_node_manager.log
    Critical operations, errors, and hardware allocation events are logged
"""

import os
import glob
import yaml
import time
import logging
import subprocess
from typing import Dict, List, Optional, Tuple

# Configure logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# Constants
DEFAULT_INTERVAL = 30
DEFAULT_BASE_PATH = '/opt/so/saltstack/local/salt/hypervisor/hosts'
VALID_ROLES = ['sensor', 'searchnode', 'idh', 'receiver', 'heavynode', 'fleet']
MAX_RETRIES = 3
RETRY_DELAY = 5
LICENSE_PATH = '/opt/so/saltstack/local/pillar/soc/license.sls'

def ensure_claimed_section(hw_config: dict) -> dict:
    """
    Ensure the claimed section exists and is a dict.
    
    Args:
        hw_config: Hardware configuration section containing 'claimed' key
    
    Returns:
        The claimed section as a dict
    """
    if hw_config['claimed'] is None or not isinstance(hw_config['claimed'], dict):
        hw_config['claimed'] = {}
    return hw_config['claimed']

def convert_pci_id(pci_id: str) -> str:
    """
    Convert PCI ID from pci_0000_c7_00_0 format to 0000:c7:00.0 format.
    
    Args:
        pci_id: PCI ID in underscore format (e.g., pci_0000_c7_00_0)
    
    Returns:
        PCI ID in domain:bus:slot.function format (e.g., 0000:c7:00.0)
        
    Example:
        >>> convert_pci_id('pci_0000_c7_00_0')
        '0000:c7:00.0'
    """
    # Remove 'pci_' prefix
    pci_id = pci_id.replace('pci_', '')
    
    # Split into components
    parts = pci_id.split('_')
    if len(parts) != 4:
        raise ValueError(f"Invalid PCI ID format: {pci_id}. Expected format: pci_domain_bus_slot_function")
        
    # Reconstruct with proper format (using period for function)
    domain, bus, slot, function = parts
    return f"{domain}:{bus}:{slot}.{function}"

class HardwareManager:
    """
    Manages hardware allocation and tracking for virtual machines.
    Handles reading hypervisor configuration, claiming PCI devices,
    and maintaining hardware tracking files.
    """
    
    def __init__(self, hypervisor: str, base_path: str):
        """Initialize the hardware manager for a specific hypervisor."""
        self.hypervisor = hypervisor
        self.base_path = base_path
        self.hypervisor_file = os.path.join(base_path, hypervisor, f"{hypervisor}.yaml")

    def read_hypervisor_config(self) -> dict:
        """
        Read and initialize the hypervisor's hardware configuration file.
        Ensures all hardware sections have a valid claimed section.
        """
        try:
            with open(self.hypervisor_file, 'r') as f:
                config = yaml.safe_load(f)
            
            # Initialize any null claimed sections
            modified = False
            for hw_type in ['disk', 'copper', 'sfp']:
                hw_config = config['hypervisor']['hardware'][hw_type]
                if hw_config['claimed'] is None:
                    log.debug("Initializing null claimed section for %s", hw_type)
                    hw_config['claimed'] = {}
                    modified = True
            
            # Save if we made any changes
            if modified:
                log.info("Updating hypervisor config with initialized claimed sections")
                self.write_hypervisor_config(config)
            
            return config
        except Exception as e:
            log.error("Failed to read hypervisor configuration: %s", str(e))
            raise

    def write_hypervisor_config(self, config: dict) -> None:
        """Write updated configuration back to the hypervisor file."""
        try:
            with open(self.hypervisor_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
        except Exception as e:
            log.error("Failed to write hypervisor configuration: %s", str(e))
            raise

    def get_pci_ids(self, hw_type: str, indices: List[int]) -> List[str]:
        """
        Look up PCI IDs for requested hardware indices.
        
        Args:
            hw_type: Type of hardware (disk, copper, sfp)
            indices: List of hardware indices to look up
        
        Returns:
            List of PCI IDs
        """
        config = self.read_hypervisor_config()
        log.debug("Full config structure: %s", config)
        log.debug("Looking up indices %s for hardware type %s", indices, hw_type)
        pci_ids = []
        
        try:
            hardware_section = config['hypervisor']['hardware']
            log.debug("Hardware section: %s", hardware_section)
            if hw_type not in hardware_section:
                raise ValueError(f"Hardware type {hw_type} not found in configuration")
            
            hw_config = hardware_section[hw_type]
            free_hw = hw_config['free']
            claimed_hw = ensure_claimed_section(hw_config)
            
            log.debug("Free hardware section for %s: %s", hw_type, free_hw)
            log.debug("Claimed hardware section for %s: %s", hw_type, claimed_hw)
            
            for idx in indices:
                if idx in free_hw:
                    pci_id = convert_pci_id(free_hw[idx])
                    log.debug("Converting PCI ID from %s to %s", free_hw[idx], pci_id)
                    pci_ids.append(pci_id)
                elif idx in claimed_hw:
                    raise ValueError(f"Hardware index {idx} for {hw_type} is already claimed")
                else:
                    raise ValueError(f"Hardware index {idx} for {hw_type} does not exist")
        except KeyError as e:
            log.error("Invalid hardware configuration structure: %s", str(e))
            raise
            
        return pci_ids

    def claim_hardware(self, hw_type: str, indices: List[int]) -> None:
        """
        Move hardware from free to claimed in the hypervisor configuration.
        
        Args:
            hw_type: Type of hardware (disk, copper, sfp)
            indices: List of hardware indices to claim
        """
        config = self.read_hypervisor_config()
        
        try:
            hw_config = config['hypervisor']['hardware'][hw_type]
            ensure_claimed_section(hw_config)
            
            for idx in indices:
                if idx in hw_config['free']:
                    pci_id = hw_config['free'][idx]
                    hw_config['claimed'][idx] = pci_id
                    del hw_config['free'][idx]
                else:
                    raise ValueError(f"{hw_type} hardware index {idx} not available")
            
            self.write_hypervisor_config(config)
            log.info("Successfully claimed %s hardware indices: %s", hw_type, indices)
        except Exception as e:
            log.error("Failed to claim hardware: %s", str(e))
            raise

    def create_vm_hardware_file(self, hostname: str, role: str, hardware: dict) -> None:
        """
        Create a YAML file tracking hardware allocated to a VM.
        
        Args:
            hostname: Name of the VM
            role: VM role (sensor, searchnode, etc.)
            hardware: Dictionary of allocated hardware
        """
        vm_file = os.path.join(self.base_path, self.hypervisor, f"{hostname}_{role}.yaml")
        try:
            with open(vm_file, 'w') as f:
                yaml.dump({'hardware': hardware}, f, default_flow_style=False)
            log.info("Created hardware tracking file for %s_%s", hostname, role)
        except Exception as e:
            log.error("Failed to create VM hardware file: %s", str(e))
            raise

def validate_hvn_license() -> bool:
    """Check if the license file exists and contains required values."""
    if not os.path.exists(LICENSE_PATH):
        log.error("LICENSE: License file not found at %s", LICENSE_PATH)
        return False
        
    try:
        with open(LICENSE_PATH, 'r') as f:
            license_data = yaml.safe_load(f)
            
        if not license_data:
            log.error("LICENSE: Empty or invalid license file")
            return False
            
        license_id = license_data.get('license_id')
        features = license_data.get('features', [])
        
        if not license_id:
            log.error("LICENSE: No license_id found in license file")
            return False
            
        if 'hvn' not in features:
            log.error("Hypervisor nodes are a feature supported only for customers with a valid license.\n"
                     "Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com\n"
                     "for more information about purchasing a license to enable this feature.")
            return False
            
        log.info("LICENSE: License validation successful")
        return True
            
    except Exception as e:
        log.error("LICENSE: Error reading license file: %s", str(e))
        return False

def parse_add_file(file_path: str) -> Tuple[str, str, dict]:
    """
    Parse an add_* file to extract VM configuration.
    
    Returns:
        Tuple of (hypervisor, role, config)
    """
    try:
        # Extract hypervisor and role from path
        path_parts = file_path.split(os.path.sep)
        hypervisor = path_parts[-2]
        role = path_parts[-1].replace('add_', '')
        
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role: {role}")
        
        # Read and parse YAML configuration
        with open(file_path, 'r') as f:
            config = yaml.safe_load(f)
            
        required_fields = ['hostname', 'network_mode']
        if config.get('network_mode') == 'static4':
            required_fields.extend(['ip4', 'gw4'])
            
        for field in required_fields:
            if field not in config:
                raise ValueError(f"Missing required field: {field}")
                
        return hypervisor, role, config
    except Exception as e:
        log.error("Failed to parse add file %s: %s", file_path, str(e))
        raise

def convert_gb_to_mib(gb: int) -> int:
    """
    Convert memory value from GB to MiB.
    
    Args:
        gb: Memory value in gigabytes
        
    Returns:
        Memory value in mebibytes (1 GB = 1024 MiB)
    """
    return gb * 1024

def execute_salt_cloud(profile: str, hostname: str, role: str, config: dict, pci_ids: List[str]) -> None:
    """
    Execute so-salt-cloud to create the VM.
    
    Args:
        profile: Salt cloud profile name
        hostname: VM hostname
        role: VM role
        config: VM configuration
        pci_ids: List of PCI IDs for hardware passthrough
    """
    try:
        cmd = ['so-salt-cloud', '-p', f'sool9-{profile}', f'{hostname}_{role}']
        
        # Add network configuration
        if config['network_mode'] == 'static4':
            cmd.extend(['--static4', '--ip4', config['ip4'], '--gw4', config['gw4']])
            if 'dns4' in config:
                cmd.extend(['--dns4', ','.join(config['dns4'])])
            if 'search4' in config:
                cmd.extend(['--search4', config['search4']])
        else:
            cmd.append('--dhcp4')
            
        # Add hardware configuration
        if 'cpu' in config:
            cmd.extend(['-c', str(config['cpu'])])
        if 'memory' in config:
            # Convert memory from GB to MiB for so-salt-cloud
            memory_mib = convert_gb_to_mib(config['memory'])
            cmd.extend(['-m', str(memory_mib)])
            
        # Add PCI devices
        for pci_id in pci_ids:
            cmd.extend(['-P', pci_id])
            
        log.info("Executing: %s", ' '.join(cmd))
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        log.error("so-salt-cloud execution failed: %s", str(e))
        raise
    except Exception as e:
        log.error("Failed to execute so-salt-cloud: %s", str(e))
        raise

def process_add_file(file_path: str, base_path: str) -> None:
    """
    Process a single add_* file for VM creation.
    
    Args:
        file_path: Path to the add_* file
        base_path: Base path for hypervisor configuration
    """
    try:
        hypervisor, role, config = parse_add_file(file_path)
        log.debug("Parsed config from add file: %s", config)
        hw_manager = HardwareManager(hypervisor, base_path)
        
        # Collect all PCI IDs
        pci_ids = []
        hardware_tracking = {
            'cpu': config.get('cpu'),
            'memory': config.get('memory')
        }
        
        # Process each hardware type
        for hw_type in ['disk', 'copper', 'sfp']:
            if hw_type in config:
                indices = config[hw_type]
                hw_pci_ids = hw_manager.get_pci_ids(hw_type, indices)
                pci_ids.extend(hw_pci_ids)
                
                # Track hardware allocation
                hardware_tracking[hw_type] = [
                    {'id': idx, 'pci': pci_id}
                    for idx, pci_id in zip(indices, hw_pci_ids)
                ]
                
                # Claim the hardware
                hw_manager.claim_hardware(hw_type, indices)
        
        # Create VM
        execute_salt_cloud(hypervisor, config['hostname'], role, config, pci_ids)
        
        # Create hardware tracking file
        hw_manager.create_vm_hardware_file(config['hostname'], role, hardware_tracking)
        
        # Clean up the add_* file
        os.remove(file_path)
        log.info("Successfully processed VM creation request: %s_%s", config['hostname'], role)
        
    except Exception as e:
        log.error("Failed to process add file %s: %s", file_path, str(e))
        raise

def monitor_add_files(base_path: str) -> None:
    """
    Monitor directories for add_* files and process them.
    
    Args:
        base_path: Base path to monitor for add_* files
    """
    pattern = os.path.join(base_path, '*', 'add_*')
    
    try:
        for file_path in glob.glob(pattern):
            log.info("Found new VM request file: %s", file_path)
            
            for attempt in range(MAX_RETRIES):
                try:
                    process_add_file(file_path, base_path)
                    break
                except Exception as e:
                    if attempt < MAX_RETRIES - 1:
                        log.warning("Attempt %d failed, retrying in %d seconds: %s",
                                  attempt + 1, RETRY_DELAY, str(e))
                        time.sleep(RETRY_DELAY)
                    else:
                        log.error("All attempts failed for file %s", file_path)
                        raise
    except Exception as e:
        log.error("Error monitoring add files: %s", str(e))
        raise

def start(interval: int = DEFAULT_INTERVAL,
          base_path: str = DEFAULT_BASE_PATH) -> None:
    """
    Main engine loop.
    
    Args:
        interval: Time in seconds between directory scans
        base_path: Base path to monitor for VM requests
    """
    log.info("Starting virtual node manager engine")
    
    if not validate_hvn_license():
        return
    
    while True:
        try:
            monitor_add_files(base_path)
        except Exception as e:
            log.error("Error in main engine loop: %s", str(e))
        
        time.sleep(interval)
