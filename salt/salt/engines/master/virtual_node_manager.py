#!/opt/saltstack/salt/bin/python3

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
Salt Engine for Virtual Node Management

This engine manages the automated provisioning of virtual machines in Security Onion's
virtualization infrastructure. It processes VM configurations from a nodes file and handles
the entire provisioning process including hardware allocation, state tracking, and file ownership.

Usage:
    engines:
      - virtual_node_manager:
          interval: 30
          base_path: /opt/so/saltstack/local/salt/hypervisor/hosts

Options:
    interval: Time in seconds between engine runs (managed by salt-master, default: 30)
    base_path: Base directory containing hypervisor configurations (default: /opt/so/saltstack/local/salt/hypervisor/hosts)
    
    Memory values in VM configuration should be specified in GB. These values
    will automatically be converted to MiB when passed to so-salt-cloud.

Configuration Files:
    nodes: JSON file containing VM configurations
        - Located at <base_path>/<hypervisor>/nodes
        - Contains array of VM configurations
        - Each VM config specifies hardware and network settings

    defaults.yaml: Hardware capabilities configuration
        - Located at /opt/so/saltstack/default/salt/hypervisor/defaults.yaml
        - Defines available hardware per model
        - Maps hardware indices to PCI IDs

Examples:
    1. Basic Configuration:
        engines:
          - virtual_node_manager: {}
        
        Uses default settings to process VM configurations.

    2. Custom Interval:
        engines:
          - virtual_node_manager:
              interval: 60
        
        Processes configurations every 60 seconds.

State Files:
    VM Tracking Files:
        - <vm_name>: Active VM with status 'creating' or 'running'
        - <vm_name>.error: Error state with detailed message
Notes:
    - Requires 'hvn' feature license
    - Uses hypervisor's sosmodel grain for hardware capabilities
    - Hardware allocation based on model-specific configurations
    - All created files maintain socore ownership
    - Comprehensive logging for troubleshooting
    - Single engine-wide lock prevents concurrent instances
    - Lock remains if error occurs (requires admin intervention)

Description:
   The engine operates in the following phases:

   1. Engine Lock Acquisition
      - Acquires single engine-wide lock
      - Prevents multiple instances from running
      - Lock remains until clean shutdown or error

   2. License Validation
      - Verifies 'hvn' feature is licensed
      - Prevents operation if license is invalid

   3. Configuration Processing
      - Reads nodes file from each hypervisor directory
      - Validates configuration parameters
      - Compares against existing VM tracking files

   4. Hardware Allocation
      - Retrieves hypervisor model from grains cache
      - Loads model-specific hardware capabilities
      - Validates hardware requests against model limits
      - Converts hardware indices to PCI IDs
      - Ensures proper type handling for hardware indices
      - Creates state tracking files with socore ownership

   5. VM Provisioning
      - Executes so-salt-cloud with validated configuration
      - Handles network setup (static/DHCP)
      - Configures hardware passthrough with converted PCI IDs
      - Updates VM state tracking

   Lock Management:
      - Lock acquired at engine start
      - Released only on clean shutdown
      - Remains if error occurs
      - Admin must restart service to clear lock
      - Error-level logging for lock issues

Exit Codes:
    0: Success
    1: Invalid license
    2: Configuration error
    3: Hardware validation failure (hardware doesn't exist in model or is already in use by another VM)
    4: VM provisioning failure (so-salt-cloud execution failed)

Logging:
    Log files are written to /opt/so/log/salt/engines/virtual_node_manager.log
    Comprehensive logging includes:
    - Hardware validation details
    - PCI ID conversion process
    - Command execution details
    - Error conditions with full context
    - File ownership operations
    - Lock file management
"""

import os
import glob
import yaml
import json
import time
import logging
import subprocess
import pwd
import grp
import salt.config
import salt.runner
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from threading import Lock

# Get socore uid/gid
SOCORE_UID = pwd.getpwnam('socore').pw_uid
SOCORE_GID = grp.getgrnam('socore').gr_gid

# Initialize Salt runner once
opts = salt.config.master_config('/etc/salt/master')
opts['output'] = 'json'
runner = salt.runner.RunnerClient(opts)

# Configure logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# Constants
DEFAULT_INTERVAL = 30
DEFAULT_BASE_PATH = '/opt/so/saltstack/local/salt/hypervisor/hosts'
VALID_ROLES = ['sensor', 'searchnode', 'idh', 'receiver', 'heavynode', 'fleet']
LICENSE_PATH = '/opt/so/saltstack/local/pillar/soc/license.sls'
DEFAULTS_PATH = '/opt/so/saltstack/default/salt/hypervisor/defaults.yaml'

# Single engine-wide lock for virtual node manager
engine_lock = Lock()

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

def set_socore_ownership(path: str) -> None:
    """Set socore ownership on file or directory."""
    try:
        os.chown(path, SOCORE_UID, SOCORE_GID)
        log.debug("Set socore ownership on %s", path)
    except Exception as e:
        log.error("Failed to set socore ownership on %s: %s", path, str(e))
        raise

def write_json_file(file_path: str, data: Any) -> None:
    """Write data to a JSON file with socore ownership."""
    try:
        # Create parent directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        set_socore_ownership(file_path)
    except Exception as e:
        log.error("Failed to write JSON file %s: %s", file_path, str(e))
        raise

def read_yaml_file(file_path: str) -> dict:
    """Read and parse a YAML file."""
    try:
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        log.error("Failed to read YAML file %s: %s", file_path, str(e))
        raise

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
    try:
        # Remove 'pci_' prefix
        pci_id = pci_id.replace('pci_', '')
        
        # Split into components
        parts = pci_id.split('_')
        if len(parts) != 4:
            raise ValueError(f"Invalid PCI ID format: {pci_id}. Expected format: pci_domain_bus_slot_function")
            
        # Reconstruct with proper format (using period for function)
        domain, bus, slot, function = parts
        return f"{domain}:{bus}:{slot}.{function}"
    except Exception as e:
        log.error("Failed to convert PCI ID %s: %s", pci_id, str(e))
        raise

def get_hypervisor_model(hypervisor: str) -> str:
    """Get sosmodel from hypervisor grains."""
    try:
        # Get cached grains using Salt runner
        grains = runner.cmd(
            'cache.grains',
            [f'{hypervisor}_*', 'glob']
        )
        if not grains:
            raise ValueError(f"No grains found for hypervisor {hypervisor}")
            
        # Get the first minion ID that matches our hypervisor
        minion_id = next(iter(grains.keys()))
        model = grains[minion_id].get('sosmodel')
        if not model:
            raise ValueError(f"No sosmodel grain found for hypervisor {hypervisor}")
            
        log.debug("Found model %s for hypervisor %s", model, hypervisor)
        return model
        
    except Exception as e:
        log.error("Failed to get hypervisor model: %s", str(e))
        raise

def load_hardware_defaults(model: str) -> dict:
    """Load hardware configuration from defaults.yaml."""
    try:
        defaults = read_yaml_file(DEFAULTS_PATH)
        if not defaults or 'hypervisor' not in defaults:
            raise ValueError("Invalid defaults.yaml structure")
        if 'model' not in defaults['hypervisor']:
            raise ValueError("No model configurations found in defaults.yaml")
        if model not in defaults['hypervisor']['model']:
            raise ValueError(f"Model {model} not found in defaults.yaml")
        return defaults['hypervisor']['model'][model]
    except Exception as e:
        log.error("Failed to load hardware defaults: %s", str(e))
        raise

def validate_hardware_request(model_config: dict, requested_hw: dict) -> Tuple[bool, Optional[dict]]:
    """
    Validate hardware request against model capabilities.
    
    Returns:
        Tuple of (is_valid, error_details)
    """
    errors = {}
    log.debug("Validating if requested hardware exists in model configuration")
    log.debug("Requested hardware: %s", requested_hw)
    log.debug("Model hardware configuration: %s", model_config['hardware'])
    
    # Validate CPU
    if 'cpu' in requested_hw:
        try:
            cpu_count = int(requested_hw['cpu'])
            log.debug("Checking if %d CPU cores exist in model (maximum: %d)",
                     cpu_count, model_config['hardware']['cpu'])
            if cpu_count > model_config['hardware']['cpu']:
                errors['cpu'] = f"Requested {cpu_count} CPU cores exceeds maximum {model_config['hardware']['cpu']}"
        except ValueError:
            errors['cpu'] = "Invalid CPU value"

    # Validate Memory
    if 'memory' in requested_hw:
        try:
            memory = int(requested_hw['memory'])
            log.debug("Checking if %dGB memory exists in model (maximum: %dGB)",
                     memory, model_config['hardware']['memory'])
            if memory > model_config['hardware']['memory']:
                errors['memory'] = f"Requested {memory}GB memory exceeds maximum {model_config['hardware']['memory']}GB"
        except ValueError:
            errors['memory'] = "Invalid memory value"

    # Validate PCI devices
    for hw_type in ['disk', 'copper', 'sfp']:
        if hw_type in requested_hw and requested_hw[hw_type]:
            try:
                indices = [int(x) for x in str(requested_hw[hw_type]).split(',')]
                log.debug("Checking if %s indices %s exist in model", hw_type, indices)
                
                if hw_type not in model_config['hardware']:
                    log.error("Hardware type %s not found in model config", hw_type)
                    errors[hw_type] = f"No {hw_type} configuration found in model"
                    continue
                    
                model_indices = set(int(k) for k in model_config['hardware'][hw_type].keys())
                log.debug("Model has %s indices: %s", hw_type, model_indices)
                
                invalid_indices = [idx for idx in indices if idx not in model_indices]
                if invalid_indices:
                    log.error("%s indices %s do not exist in model", hw_type, invalid_indices)
                    errors[hw_type] = f"Invalid {hw_type} indices: {invalid_indices}"
            except ValueError:
                log.error("Invalid %s indices format: %s", hw_type, requested_hw[hw_type])
                errors[hw_type] = f"Invalid {hw_type} indices format"
            except KeyError:
                log.error("No %s configuration found in model", hw_type)
                errors[hw_type] = f"No {hw_type} configuration found in model"

    if errors:
        log.error("Hardware validation failed with errors: %s", errors)
    else:
        log.debug("Hardware validation successful")
        
    return (len(errors) == 0, errors if errors else None)

def check_hardware_availability(hypervisor_path: str, vm_name: str, requested_hw: dict, model_config: dict) -> Tuple[bool, Optional[dict]]:
    """
    Check if requested hardware is available.
    
    Args:
        hypervisor_path: Path to hypervisor directory
        vm_name: Name of requesting VM
        requested_hw: Hardware being requested
        model_config: Model hardware configuration
    
    Returns:
        Tuple of (is_available, error_details)
    """
    log.debug("Checking if requested hardware is currently in use by other VMs")
    log.debug("VM requesting hardware: %s", vm_name)
    log.debug("Hardware being requested: %s", requested_hw)
    
    errors = {}
    
    # Track total CPU/memory usage
    total_cpu = 0
    total_memory = 0
    
    # Track used unique resources and which VM is using them
    used_resources = {
        'disk': {},    # {index: vm_name}
        'copper': {},  # {index: vm_name}
        'sfp': {}      # {index: vm_name}
    }
    
    # Calculate current usage from existing VMs
    log.debug("Scanning existing VMs to check hardware usage")
    for vm_file in glob.glob(os.path.join(hypervisor_path, '*_*')):
        basename = os.path.basename(vm_file)
        # Skip if it's the same VM requesting hardware or in error state
        if basename.startswith(vm_name):
            log.debug("Skipping file %s (same VM requesting hardware)", basename)
            continue
        if basename.endswith('.error'):
            log.debug("Skipping file %s (error state)", basename)
            continue
            
        vm_config = read_json_file(vm_file)
        if 'config' not in vm_config or vm_config.get('status') != 'running':
            log.debug("Skipping VM %s (not running)", basename)
            continue
            
        config = vm_config['config']
        log.debug("Processing running VM %s", basename)
        
        # Add to CPU/memory totals
        vm_cpu = int(config.get('cpu', 0))
        vm_memory = int(config.get('memory', 0))
        total_cpu += vm_cpu
        total_memory += vm_memory
        log.debug("Found running VM %s using CPU: %d, Memory: %dGB", basename, vm_cpu, vm_memory)
        
        # Track unique resources
        for hw_type in ['disk', 'copper', 'sfp']:
            if hw_type in config and config[hw_type]:
                indices = [int(x) for x in str(config[hw_type]).split(',')]
                for idx in indices:
                    used_resources[hw_type][idx] = basename.replace('_sensor', '')  # Store VM name without role
                log.debug("VM %s is using %s indices: %s", basename, hw_type, indices)
    
    log.debug("Total hardware currently in use - CPU: %d, Memory: %dGB", total_cpu, total_memory)
    log.debug("Hardware indices currently in use: %s", used_resources)
    
    # Check CPU capacity
    requested_cpu = int(requested_hw.get('cpu', 0))
    total_cpu_needed = total_cpu + requested_cpu
    log.debug("Checking CPU capacity - Currently in use: %d + Requested: %d = %d (Max: %d)",
             total_cpu, requested_cpu, total_cpu_needed, model_config['hardware']['cpu'])
    if total_cpu_needed > model_config['hardware']['cpu']:
        errors['cpu'] = f"Total CPU usage ({total_cpu_needed}) would exceed capacity ({model_config['hardware']['cpu']})"
    
    # Check memory capacity
    requested_memory = int(requested_hw.get('memory', 0))
    total_memory_needed = total_memory + requested_memory
    log.debug("Checking memory capacity - Currently in use: %d + Requested: %d = %d (Max: %d)",
             total_memory, requested_memory, total_memory_needed, model_config['hardware']['memory'])
    if total_memory_needed > model_config['hardware']['memory']:
        errors['memory'] = f"Total memory usage ({total_memory_needed}GB) would exceed capacity ({model_config['hardware']['memory']}GB)"
    
    # Check for hardware conflicts
    for hw_type in ['disk', 'copper', 'sfp']:
        if hw_type in requested_hw and requested_hw[hw_type]:
            requested_indices = [int(x) for x in str(requested_hw[hw_type]).split(',')]
            log.debug("Checking for %s conflicts - Requesting indices: %s, Currently in use: %s",
                     hw_type, requested_indices, used_resources[hw_type])
            conflicts = {}  # {index: vm_name}
            for idx in requested_indices:
                if idx in used_resources[hw_type]:
                    conflicts[idx] = used_resources[hw_type][idx]
            
            if conflicts:
                # Create one sentence per conflict
                conflict_details = []
                hw_name = hw_type.upper() if hw_type == 'sfp' else hw_type.capitalize()
                for idx, vm in conflicts.items():
                    conflict_details.append(f"{hw_name} index {idx} in use by {vm}")
                
                log.debug("Found conflicting %s indices: %s", hw_type, conflict_details)
                errors[hw_type] = ". ".join(conflict_details) + "."
    
    if errors:
        log.debug("Hardware validation failed with errors: %s", errors)
    else:
        log.debug("Hardware validation successful")
    
    return (len(errors) == 0, errors if errors else None)

def create_vm_tracking_file(hypervisor_path: str, vm_name: str, config: dict) -> None:
    """Create VM tracking file with initial state."""
    file_path = os.path.join(hypervisor_path, vm_name)
    log.debug("Creating VM tracking file at %s", file_path)
    try:
        # Create parent directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        set_socore_ownership(os.path.dirname(file_path))
        
        data = {
            'config': config,
            'status': 'creating'
        }
        # Write file and set ownership
        write_json_file(file_path, data)
        log.debug("Successfully created VM tracking file with socore ownership")
    except Exception as e:
        log.error("Failed to create VM tracking file: %s", str(e))
        raise

def mark_vm_failed(vm_file: str, error_code: int, message: str) -> None:
    """Create error file with VM failure details."""
    try:
        # Get original config if it exists
        config = {}
        if os.path.exists(vm_file):
            data = read_json_file(vm_file)
            config = data.get('config', {})
            # Remove the original file since we'll create an error file
            os.remove(vm_file)

        # Create error file
        error_file = f"{vm_file}.error"
        data = {
            'config': config,
            'status': 'error',
            'error_details': {
                'message': message,
                'timestamp': datetime.now().isoformat()
            }
        }
        write_json_file(error_file, data)
    except Exception as e:
        log.error("Failed to create error file: %s", str(e))
        raise

def mark_invalid_hardware(hypervisor_path: str, vm_name: str, config: dict, error_details: dict) -> None:
    """Create error file with hardware validation failure details."""
    file_path = os.path.join(hypervisor_path, f"{vm_name}.error")
    try:
        # Build error message from error details
        error_messages = []
        for hw_type, message in error_details.items():
            error_messages.append(message)
        
        # Join all messages with proper sentence structure
        full_message = "Hardware validation failure: " + " ".join(error_messages)
        
        data = {
            'config': config,
            'status': 'error',
            'error_details': {
                'message': full_message,
                'timestamp': datetime.now().isoformat()
            }
        }
        write_json_file(file_path, data)
    except Exception as e:
        log.error("Failed to create invalid hardware file: %s", str(e))
        raise

def validate_hvn_license() -> bool:
    """Check if the license file exists and contains required values."""
    if not os.path.exists(LICENSE_PATH):
        log.error("License file not found at %s", LICENSE_PATH)
        return False
        
    try:
        with open(LICENSE_PATH, 'r') as f:
            license_data = yaml.safe_load(f)
            
        if not license_data:
            log.error("Empty or invalid license file")
            return False
            
        license_id = license_data.get('license_id')
        features = license_data.get('features', [])
        
        if not license_id:
            log.error("No license_id found in license file")
            return False
            
        if 'hvn' not in features:
            log.error("Hypervisor nodes are a feature supported only for customers with a valid license.\n"
                     "Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com\n"
                     "for more information about purchasing a license to enable this feature.")
            return False
            
        log.info("License validation successful")
        return True
            
    except Exception as e:
        log.error("Error reading license file: %s", str(e))
        return False

def process_vm_creation(hypervisor_path: str, vm_config: dict) -> None:
    """
    Process a single VM creation request.
    
    This function handles the creation of a new VM, including hardware validation,
    resource allocation, and provisioning. All operations are protected by the
    engine-wide lock that is acquired at engine start.
    
    Args:
        hypervisor_path: Path to the hypervisor directory
        vm_config: Dictionary containing VM configuration
    """
    # Get the actual hypervisor name (last directory in path)
    hypervisor = os.path.basename(hypervisor_path)
    vm_name = f"{vm_config['hostname']}_{vm_config['role']}"
    
    try:
        # Get hypervisor model and capabilities
        model = get_hypervisor_model(hypervisor)
        model_config = load_hardware_defaults(model)

        # Initial hardware validation against model
        is_valid, errors = validate_hardware_request(model_config, vm_config)
        if not is_valid:
            mark_invalid_hardware(hypervisor_path, vm_name, vm_config, errors)
            return

        # Check hardware availability
        is_available, availability_errors = check_hardware_availability(
            hypervisor_path, vm_name, vm_config, model_config)
        if not is_available:
            mark_invalid_hardware(hypervisor_path, vm_name, vm_config, availability_errors)
            return

        # Create tracking file
        create_vm_tracking_file(hypervisor_path, vm_name, vm_config)

        # Build and execute so-salt-cloud command
        cmd = ['so-salt-cloud', '-p', f'sool9-{hypervisor}', vm_name]
        
        # Add network configuration
        if vm_config['network_mode'] == 'static4':
            cmd.extend(['--static4', '--ip4', vm_config['ip4'], '--gw4', vm_config['gw4']])
            if 'dns4' in vm_config:
                cmd.extend(['--dns4', vm_config['dns4']])
            if 'search4' in vm_config:
                cmd.extend(['--search4', vm_config['search4']])
        else:
            cmd.append('--dhcp4')
            
        # Add hardware configuration
        if 'cpu' in vm_config:
            cmd.extend(['-c', str(vm_config['cpu'])])
        if 'memory' in vm_config:
            memory_mib = int(vm_config['memory']) * 1024
            cmd.extend(['-m', str(memory_mib)])
            
        # Add PCI devices
        for hw_type in ['disk', 'copper', 'sfp']:
            if hw_type in vm_config and vm_config[hw_type]:
                indices = [int(x) for x in str(vm_config[hw_type]).split(',')]
                for idx in indices:
                    hw_config = {int(k): v for k, v in model_config['hardware'][hw_type].items()}
                    pci_id = hw_config[idx]
                    converted_pci_id = convert_pci_id(pci_id)
                    cmd.extend(['-P', converted_pci_id])
            
        # Execute command
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Update tracking file status
        tracking_file = os.path.join(hypervisor_path, vm_name)
        data = read_json_file(tracking_file)
        data['status'] = 'running'
        write_json_file(tracking_file, data)
        
    except subprocess.CalledProcessError as e:
        error_msg = f"so-salt-cloud execution failed (code {e.returncode})"
        if e.stderr:
            error_msg = f"{error_msg}: {e.stderr}"
        log.error(error_msg)
        mark_vm_failed(os.path.join(hypervisor_path, vm_name), 4, error_msg)
        raise
    except Exception as e:
        error_msg = f"VM creation failed: {str(e)}"
        log.error(error_msg)
        if not os.path.exists(os.path.join(hypervisor_path, vm_name)):
            mark_vm_failed(os.path.join(hypervisor_path, f"{vm_name}_failed"), 4, error_msg)
        raise

def process_vm_deletion(hypervisor_path: str, vm_name: str) -> None:
    """
    Process a single VM deletion request.
    
    This function handles the deletion of an existing VM. All operations are protected
    by the engine-wide lock that is acquired at engine start.
    
    Args:
        hypervisor_path: Path to the hypervisor directory
        vm_name: Name of the VM to delete
    """
    try:
        # Get the actual hypervisor name (last directory in path)
        hypervisor = os.path.basename(hypervisor_path)
        cmd = ['so-salt-cloud', '-p', f'sool9-{hypervisor}', vm_name, '-yd']
        
        log.info("Executing: %s", ' '.join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Log command output
        if result.stdout:
            log.debug("Command stdout: %s", result.stdout)
        if result.stderr:
            log.warning("Command stderr: %s", result.stderr)
            
        # Remove VM tracking file
        vm_file = os.path.join(hypervisor_path, vm_name)
        if os.path.exists(vm_file):
            os.remove(vm_file)
            log.info("Successfully removed VM tracking file")
            
    except subprocess.CalledProcessError as e:
        error_msg = f"so-salt-cloud deletion failed (code {e.returncode}): {e.stderr}"
        log.error(error_msg)
        raise
    except Exception as e:
        log.error("Error processing VM deletion: %s", str(e))
        raise

def process_hypervisor(hypervisor_path: str) -> None:
    """
    Process VM configurations for a single hypervisor.
    
    This function handles the processing of VM configurations for a hypervisor,
    including creation of new VMs and deletion of removed VMs. All operations
    are protected by the engine-wide lock that is acquired at engine start.
    
    The function performs the following steps:
    1. Reads and validates nodes configuration
    2. Identifies existing VMs
    3. Processes new VM creation requests
    4. Handles VM deletions for removed configurations
    
    Args:
        hypervisor_path: Path to the hypervisor directory
    """
    try:
        # Detection phase - no lock needed
        nodes_file = os.path.join(hypervisor_path, 'nodes')
        if not os.path.exists(nodes_file):
            return
            
        nodes_config = read_json_file(nodes_file)
        if not nodes_config:
            return
            
        # Get existing VMs - no lock needed
        existing_vms = set()
        for file_path in glob.glob(os.path.join(hypervisor_path, '*_*')):
            basename = os.path.basename(file_path)
            if not basename.endswith('.error'):
                existing_vms.add(basename)
                
        # Process new VMs
        configured_vms = set()
        for vm_config in nodes_config:
            if 'hostname' not in vm_config or 'role' not in vm_config:
                log.error("Invalid VM configuration: missing hostname or role")
                continue
                
            vm_name = f"{vm_config['hostname']}_{vm_config['role']}"
            configured_vms.add(vm_name)
            
            if vm_name not in existing_vms:
                # process_vm_creation handles its own locking
                process_vm_creation(hypervisor_path, vm_config)
                
        # Process VM deletions
        for vm_name in existing_vms - configured_vms:
            process_vm_deletion(hypervisor_path, vm_name)
            
    except Exception as e:
        log.error("Failed to process hypervisor %s: %s", hypervisor_path, str(e))
        raise

def start(interval: int = DEFAULT_INTERVAL,
          base_path: str = DEFAULT_BASE_PATH) -> None:
    """
    Process virtual node configurations.
    
    This function implements a single engine-wide lock to ensure only one
    instance of the virtual node manager runs at a time. The lock is:
    - Acquired at start
    - Released after processing completes
    - Maintained if error occurs
    
    Args:
        interval: Time in seconds between engine runs (managed by salt-master)
        base_path: Base path containing hypervisor configurations
        
    Notes:
        - Lock remains if engine encounters an error
        - Admin must restart service to clear lock
        - Error-level logging used for lock issues
    """
    log.info("Starting virtual node manager engine")
    
    if not validate_hvn_license():
        return
        
    # Attempt to acquire engine lock
    if not engine_lock.acquire(blocking=False):
        log.error("Another virtual node manager is already running")
        return
    
    log.debug("Virtual node manager acquired engine lock")
        
    try:
        # Process each hypervisor directory
        for hypervisor_path in glob.glob(os.path.join(base_path, '*')):
            if os.path.isdir(hypervisor_path):
                process_hypervisor(hypervisor_path)
                
        # Clean shutdown - release lock
        log.debug("Virtual node manager releasing engine lock")
        engine_lock.release()
        log.info("Virtual node manager completed successfully")
                
    except Exception as e:
        log.error("Error in virtual node manager - lock will remain until cleared: %s", str(e))
        # Don't release lock on error - requires admin intervention
        return
