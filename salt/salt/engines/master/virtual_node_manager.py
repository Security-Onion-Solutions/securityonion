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
Salt Engine for Virtual Node Management

This engine manages the automated provisioning of virtual machines in Security Onion's
virtualization infrastructure. It processes VM configurations from a VMs file and handles
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
    <hypervisorHostname>VMs: JSON file containing VM configurations
        - Located at <base_path>/<hypervisorHostname>VMs
        - Contains array of VM configurations
        - Each VM config specifies hardware and network settings
        - Hardware indices (disk, copper, sfp) must be specified as JSON arrays: "disk":["1","2"]

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
    - Requires 'vrt' feature license
    - Uses hypervisor's sosmodel grain for hardware capabilities
    - Hardware allocation based on model-specific configurations
    - All created files maintain socore ownership
    - Comprehensive logging for troubleshooting
    - Single engine-wide lock prevents concurrent instances
    - Lock remains if error occurs (requires admin intervention)

Description:
   The engine operates in the following phases:

   1. Lock Acquisition
      - Acquires single engine-wide lock
      - Prevents multiple instances from running
      - Lock remains until clean shutdown or error

   2. License Validation
      - Verifies 'vrt' feature is licensed
      - Prevents operation if license is invalid

   3. Configuration Processing
      - Reads VMs file for each hypervisor
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
    Log files are written to /opt/so/log/salt/engines/virtual_node_manager
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
import salt.client
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from threading import Lock

# Initialize Salt runner and local client once
opts = salt.config.master_config('/etc/salt/master')
opts['output'] = 'json'
runner = salt.runner.RunnerClient(opts)
local = salt.client.LocalClient()

# Get socore uid/gid for file ownership
SOCORE_UID = pwd.getpwnam('socore').pw_uid
SOCORE_GID = grp.getgrnam('socore').gr_gid

# Configure logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# Prevent propagation to parent loggers to avoid duplicate log entries
log.propagate = False

# Add file handler for dedicated log file
log_dir = '/opt/so/log/salt'
log_file = os.path.join(log_dir, 'virtual_node_manager')

# Create log directory if it doesn't exist
os.makedirs(log_dir, exist_ok=True)

# Create file handler
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.DEBUG)

# Create formatter
formatter = logging.Formatter(
    '%(asctime)s [%(name)s:%(lineno)d][%(levelname)-8s][%(process)d] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(formatter)

# Add handler to logger
log.addHandler(file_handler)

# Constants
DEFAULT_INTERVAL = 30
DEFAULT_BASE_PATH = '/opt/so/saltstack/local/salt/hypervisor/hosts'
VALID_ROLES = ['sensor', 'searchnode', 'idh', 'receiver', 'heavynode', 'fleet']
LICENSE_PATH = '/opt/so/saltstack/local/pillar/soc/license.sls'
DEFAULTS_PATH = '/opt/so/saltstack/default/salt/hypervisor/defaults.yaml'
HYPERVISOR_PILLAR_PATH = '/opt/so/saltstack/local/pillar/hypervisor/soc_hypervisor.sls'
# Define the retention period for destroyed VMs (in hours)
DESTROYED_VM_RETENTION_HOURS = 48

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
def remove_vm_from_vms_file(vms_file_path: str, vm_hostname: str, vm_role: str) -> bool:
    """
    Remove a VM entry from the hypervisorVMs file.
    
    Args:
        vms_file_path: Path to the hypervisorVMs file
        vm_hostname: Hostname of the VM to remove (without role suffix)
        vm_role: Role of the VM
        
    Returns:
        bool: True if VM was removed, False otherwise
    """
    try:
        # Read current VMs
        vms = read_json_file(vms_file_path)
        
        # Find and remove the VM entry
        original_count = len(vms)
        vms = [vm for vm in vms if not (vm.get('hostname') == vm_hostname and vm.get('role') == vm_role)]
        
        if len(vms) < original_count:
            # VM was found and removed, write back to file
            write_json_file(vms_file_path, vms)
            log.info("Removed VM %s_%s from %s", vm_hostname, vm_role, vms_file_path)
            return True
        else:
            log.warning("VM %s_%s not found in %s", vm_hostname, vm_role, vms_file_path)
            return False
            
    except Exception as e:
        log.error("Failed to remove VM %s_%s from %s: %s", vm_hostname, vm_role, vms_file_path, str(e))
        return False


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

def parse_hardware_indices(hw_value: Any) -> List[int]:
    """
    Parse hardware indices from JSON array format.
    
    Args:
        hw_value: Hardware value which should be a list
        
    Returns:
        List of integer indices
    """
    indices = []
    
    if hw_value is None:
        return indices
        
    # If it's a list (expected format)
    if isinstance(hw_value, list):
        try:
            indices = [int(x) for x in hw_value]
            log.debug("Parsed hardware indices from list format: %s", indices)
        except (ValueError, TypeError) as e:
            log.error("Failed to parse hardware indices from list format: %s", str(e))
            raise ValueError(f"Invalid hardware indices format in list: {hw_value}")
    else:
        log.warning("Unexpected type for hardware indices: %s", type(hw_value))
        raise ValueError(f"Hardware indices must be in array format, got: {type(hw_value)}")
        
    return indices

def get_hypervisor_model(hypervisor: str) -> str:
    """Get sosmodel or byodmodel from hypervisor grains."""
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
        model = grains[minion_id].get('sosmodel', grains[minion_id].get('byodmodel', ''))
        if not model:
            raise ValueError(f"No sosmodel or byodmodel grain found for hypervisor {hypervisor}")
            
        log.debug("Found model %s for hypervisor %s", model, hypervisor)
        return model
        
    except Exception as e:
        log.error("Failed to get hypervisor model: %s", str(e))
        raise

def load_hardware_defaults(model: str) -> dict:
    """Load hardware configuration from defaults.yaml and optionally override with pillar configuration."""
    config = None
    config_source = None
    
    try:
        # First, try to load from defaults.yaml
        log.debug("Checking for model %s in %s", model, DEFAULTS_PATH)
        defaults = read_yaml_file(DEFAULTS_PATH)
        if not defaults or 'hypervisor' not in defaults:
            raise ValueError("Invalid defaults.yaml structure")
        if 'model' not in defaults['hypervisor']:
            raise ValueError("No model configurations found in defaults.yaml")
        
        # Check if model exists in defaults
        if model in defaults['hypervisor']['model']:
            config = defaults['hypervisor']['model'][model]
            config_source = DEFAULTS_PATH
            log.debug("Found model %s in %s", model, DEFAULTS_PATH)
        
        # Then, try to load from pillar file (if it exists)
        try:
            log.debug("Checking for model %s in %s", model, HYPERVISOR_PILLAR_PATH)
            pillar_config = read_yaml_file(HYPERVISOR_PILLAR_PATH)
            if pillar_config and 'hypervisor' in pillar_config:
                if 'model' in pillar_config['hypervisor']:
                    if model in pillar_config['hypervisor']['model']:
                        # Override with pillar configuration
                        config = pillar_config['hypervisor']['model'][model]
                        config_source = HYPERVISOR_PILLAR_PATH
                        log.debug("Found model %s in %s (overriding defaults)", model, HYPERVISOR_PILLAR_PATH)
        except FileNotFoundError:
            log.debug("Pillar file %s not found, using defaults only", HYPERVISOR_PILLAR_PATH)
        except Exception as e:
            log.warning("Failed to read pillar file %s: %s (using defaults)", HYPERVISOR_PILLAR_PATH, str(e))
        
        # If model was not found in either file, raise an error
        if config is None:
            raise ValueError(f"Model {model} not found in {DEFAULTS_PATH} or {HYPERVISOR_PILLAR_PATH}")
        
        log.debug("Using hardware configuration for model %s from %s", model, config_source)
        return config
        
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
                indices = parse_hardware_indices(requested_hw[hw_type])
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
            except ValueError as e:
                log.error("Invalid %s indices format: %s", hw_type, str(e))
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
        if 'config' not in vm_config:
            log.debug("Skipping VM %s (no config found)", basename)
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
                try:
                    indices = parse_hardware_indices(config[hw_type])
                    for idx in indices:
                        used_resources[hw_type][idx] = basename.replace('_sensor', '')  # Store VM name without role
                    log.debug("VM %s is using %s indices: %s", basename, hw_type, indices)
                except ValueError as e:
                    log.error("Error parsing %s indices for VM %s: %s", hw_type, basename, str(e))
    
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
            try:
                requested_indices = parse_hardware_indices(requested_hw[hw_type])
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
            except ValueError as e:
                log.error("Error parsing %s indices for conflict check: %s", hw_type, str(e))
                errors[hw_type] = f"Invalid {hw_type} indices format"
    
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
            'config': config
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

        # Clear hardware resource claims so failed VMs don't consume resources
        # Keep nsm_size for reference but clear cpu, memory, sfp, copper
        config.pop('cpu', None)
        config.pop('memory', None)
        config.pop('sfp', None)
        config.pop('copper', None)

        # Create error file
        error_file = f"{vm_file}.error"
        data = {
            'config': config,
            'status': 'error',
            'timestamp': datetime.now().isoformat(),
            'error_details': {
                'code': error_code,
                'message': message
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
        
        # Clear hardware resource claims so failed VMs don't consume resources
        # Keep nsm_size for reference but clear cpu, memory, sfp, copper
        config_copy = config.copy()
        config_copy.pop('cpu', None)
        config_copy.pop('memory', None)
        config_copy.pop('sfp', None)
        config_copy.pop('copper', None)
        
        data = {
            'config': config_copy,
            'status': 'error',
            'timestamp': datetime.now().isoformat(),
            'error_details': {
                'code': 3,  # Hardware validation failure code
                'message': full_message
            }
        }
        write_json_file(file_path, data)
    except Exception as e:
        log.error("Failed to create invalid hardware file: %s", str(e))
        raise

def validate_vrt_license() -> bool:
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
            
        if 'vrt' not in features:
            log.error("Hypervisor nodes are a feature supported only for customers with a valid license.\n"
                     "Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com\n"
                     "for more information about purchasing a license to enable this feature.")
            return False
            
        log.debug("License validation successful")
        return True
            
    except Exception as e:
        log.error("Error reading license file: %s", str(e))
        return False

def check_hypervisor_disk_space(hypervisor: str, size_gb: int) -> Tuple[bool, Optional[str]]:
    """
    Check if hypervisor has sufficient disk space for volume creation.
    
    Args:
        hypervisor: Hypervisor hostname
        size_gb: Required size in GB
        
    Returns:
        Tuple of (has_space, error_message)
    """
    try:
        # Get hypervisor minion ID
        hypervisor_minion = f"{hypervisor}_hypervisor"
        
        # Check disk space on /nsm/libvirt/volumes using LocalClient
        result = local.cmd(
            hypervisor_minion,
            'cmd.run',
            ["df -BG /nsm/libvirt/volumes | tail -1 | awk '{print $4}' | sed 's/G//'"]
        )
        
        if not result or hypervisor_minion not in result:
            log.error("Failed to check disk space on hypervisor %s", hypervisor)
            return False, "Failed to check disk space on hypervisor"
        
        available_gb_str = result[hypervisor_minion].strip()
        if not available_gb_str:
            log.error("Empty disk space response from hypervisor %s", hypervisor)
            return False, "Failed to get disk space information"
            
        try:
            available_gb = float(available_gb_str)
        except ValueError:
            log.error("Invalid disk space value from hypervisor %s: %s", hypervisor, available_gb_str)
            return False, f"Invalid disk space value: {available_gb_str}"
        
        # Add 10% buffer for filesystem overhead
        required_gb = size_gb * 1.1
        
        log.debug("Hypervisor %s disk space check: Available=%.2fGB, Required=%.2fGB",
                 hypervisor, available_gb, required_gb)
        
        if available_gb < required_gb:
            error_msg = f"Insufficient disk space on hypervisor {hypervisor}. Available: {available_gb:.2f}GB, Required: {required_gb:.2f}GB (including 10% overhead)"
            log.error(error_msg)
            return False, error_msg
        
        log.info("Hypervisor %s has sufficient disk space for %dGB volume", hypervisor, size_gb)
        return True, None
        
    except Exception as e:
        log.error("Error checking disk space on hypervisor %s: %s", hypervisor, str(e))
        return False, f"Error checking disk space: {str(e)}"

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

        # Send Processing status event
        try:
            subprocess.run([
                'so-salt-emit-vm-deployment-status-event',
                '-v', vm_name,
                '-H', hypervisor,
                '-s', 'Processing'
            ], check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to emit success status event: {e}")

        # Validate nsm_size if present
        if 'nsm_size' in vm_config:
            try:
                size = int(vm_config['nsm_size'])
                if size <= 0:
                    log.error("VM: %s - nsm_size must be a positive integer, got: %d", vm_name, size)
                    mark_invalid_hardware(hypervisor_path, vm_name, vm_config,
                                        {'nsm_size': 'Invalid nsm_size: must be positive integer'})
                    return
                if size > 10000:  # 10TB reasonable maximum
                    log.error("VM: %s - nsm_size %dGB exceeds reasonable maximum (10000GB)", vm_name, size)
                    mark_invalid_hardware(hypervisor_path, vm_name, vm_config,
                                        {'nsm_size': f'Invalid nsm_size: {size}GB exceeds maximum (10000GB)'})
                    return
                log.debug("VM: %s - nsm_size validated: %dGB", vm_name, size)
            except (ValueError, TypeError) as e:
                log.error("VM: %s - nsm_size must be a valid integer, got: %s", vm_name, vm_config.get('nsm_size'))
                mark_invalid_hardware(hypervisor_path, vm_name, vm_config,
                                    {'nsm_size': 'Invalid nsm_size: must be valid integer'})
                return

        # Check for conflicting storage configurations
        has_disk = 'disk' in vm_config and vm_config['disk']
        has_nsm_size = 'nsm_size' in vm_config and vm_config['nsm_size']

        if has_disk and has_nsm_size:
            log.warning("VM: %s - Both disk and nsm_size specified. disk takes precedence, nsm_size will be ignored.",
                       vm_name)

        # Check disk space BEFORE creating VM if nsm_size is specified
        if has_nsm_size and not has_disk:
            size_gb = int(vm_config['nsm_size'])
            has_space, space_error = check_hypervisor_disk_space(hypervisor, size_gb)
            if not has_space:
                log.error("VM: %s - %s", vm_name, space_error)
                
                # Send Hypervisor NSM Disk Full status event
                try:
                    subprocess.run([
                        'so-salt-emit-vm-deployment-status-event',
                        '-v', vm_name,
                        '-H', hypervisor,
                        '-s', 'Hypervisor NSM Disk Full'
                    ], check=True)
                except subprocess.CalledProcessError as e:
                    log.error("Failed to emit volume create failed event for %s: %s", vm_name, str(e))
                
                mark_invalid_hardware(
                    hypervisor_path,
                    vm_name,
                    vm_config,
                    {'disk_space': f"Insufficient disk space for {size_gb}GB volume: {space_error}"}
                )
                return
            log.debug("VM: %s - Hypervisor has sufficient space for %dGB volume", vm_name, size_gb)

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
        cmd = ['so-salt-cloud', '-p', f'sool9_{hypervisor}', vm_name]
        
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

        # Add nsm_size if specified and disk is not specified
        if 'nsm_size' in vm_config and vm_config['nsm_size'] and not ('disk' in vm_config and vm_config['disk']):
            cmd.extend(['--nsm-size', str(vm_config['nsm_size'])])
            log.debug("VM: %s - Adding nsm_size parameter: %s", vm_name, vm_config['nsm_size'])
            
        # Add PCI devices
        for hw_type in ['disk', 'copper', 'sfp']:
            if hw_type in vm_config and vm_config[hw_type]:
                try:
                    indices = parse_hardware_indices(vm_config[hw_type])
                    for idx in indices:
                        hw_config = {int(k): v for k, v in model_config['hardware'][hw_type].items()}
                        pci_id = hw_config[idx]
                        converted_pci_id = convert_pci_id(pci_id)
                        cmd.extend(['-P', converted_pci_id])
                except ValueError as e:
                    error_msg = f"Failed to parse {hw_type} indices: {str(e)}"
                    log.error(error_msg)
                    mark_vm_failed(os.path.join(hypervisor_path, vm_name), 3, error_msg)
                    raise ValueError(error_msg)
                except KeyError as e:
                    error_msg = f"Invalid {hw_type} index: {str(e)}"
                    log.error(error_msg)
                    mark_vm_failed(os.path.join(hypervisor_path, vm_name), 3, error_msg)
                    raise KeyError(error_msg)
            
        # Execute command
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Update tracking file if needed
        tracking_file = os.path.join(hypervisor_path, vm_name)
        data = read_json_file(tracking_file)
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

def cleanup_destroyed_vm_status_files(hypervisor_path: str) -> None:
    """
    Clean up status files for destroyed VMs that are older than the retention period.
    
    Args:
        hypervisor_path: Path to the hypervisor directory
    """
    try:
        log.debug(f"Using destroyed VM retention period of {DESTROYED_VM_RETENTION_HOURS} hours")
        
        # Calculate the retention cutoff time
        cutoff_time = datetime.now() - timedelta(hours=DESTROYED_VM_RETENTION_HOURS)
        
        # Find all status files for destroyed VMs
        status_files = glob.glob(os.path.join(hypervisor_path, '*_*.status'))
        log.debug(f"Found {len(status_files)} status files to check for expired destroyed VMs")
        
        for status_file in status_files:
            try:
                # Read the status file
                status_data = read_json_file(status_file)
                
                # Check if this is a destroyed VM
                if status_data.get('status') == 'Destroyed Instance':
                    # Parse the timestamp
                    timestamp_str = status_data.get('timestamp', '')
                    if timestamp_str:
                        timestamp = datetime.fromisoformat(timestamp_str)
                        vm_name = os.path.basename(status_file).replace('.status', '')
                        age_hours = (datetime.now() - timestamp).total_seconds() / 3600
                        
                        # If older than retention period, delete the file
                        if timestamp < cutoff_time:
                            log.info(f"Removing expired status file for VM {vm_name} (age: {age_hours:.1f} hours > retention: {DESTROYED_VM_RETENTION_HOURS} hours)")
                            os.remove(status_file)
                        else:
                            log.debug(f"Status file for VM {vm_name} (age: {age_hours:.1f} hours < retention: {DESTROYED_VM_RETENTION_HOURS} hours)")
            except Exception as e:
                log.error(f"Error processing status file {status_file}: {e}")
                
    except Exception as e:
        log.error(f"Failed to clean up destroyed VM status files: {e}")


def process_vm_deletion(hypervisor_path: str, vm_name: str) -> None:
    """
    Process a single VM deletion request.
    
    This function handles the deletion of an existing VM. All operations are protected
    by the engine-wide lock that is acquired at engine start.
    
    If so-salt-cloud fails during VM deletion, the function will restore the VM
    configuration back to the VMs file to maintain consistency.
    
    Args:
        hypervisor_path: Path to the hypervisor directory
        vm_name: Name of the VM to delete
    """
    vm_config = None
    hypervisor = os.path.basename(hypervisor_path)
    
    try:
        # Read VM configuration from tracking file before attempting deletion
        vm_file = os.path.join(hypervisor_path, vm_name)
        if os.path.exists(vm_file):
            try:
                vm_data = read_json_file(vm_file)
                vm_config = vm_data.get('config') if isinstance(vm_data, dict) else None
                if vm_config:
                    log.debug("Read VM config for %s before deletion", vm_name)
                else:
                    log.warning("No config found in tracking file for %s", vm_name)
            except Exception as e:
                log.warning("Failed to read VM config from tracking file %s: %s", vm_file, str(e))
        
        # Attempt VM deletion with so-salt-cloud
        cmd = ['so-salt-cloud', '-p', f'sool9_{hypervisor}', vm_name, '-yd']
        
        log.info("Executing: %s", ' '.join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Log command output
        if result.stdout:
            log.debug("Command stdout: %s", result.stdout)
        if result.stderr:
            log.warning("Command stderr: %s", result.stderr)
            
        # Remove VM tracking file on successful deletion
        if os.path.exists(vm_file):
            os.remove(vm_file)
            log.info("Successfully removed VM tracking file for %s", vm_name)
            
    except subprocess.CalledProcessError as e:
        error_msg = f"so-salt-cloud deletion failed (code {e.returncode}): {e.stderr}"
        log.error("%s", error_msg)
        log.error("Ensure all hypervisors are online. salt-cloud will fail to destroy VMs if any hypervisors are offline.")
        
        # Attempt to restore VM configuration to VMs file if we have the config
        if vm_config:
            try:
                _restore_vm_to_vms_file(hypervisor_path, hypervisor, vm_config)
            except Exception as restore_error:
                log.error("Failed to restore VM config after deletion failure: %s", str(restore_error))
        
        raise
    except Exception as e:
        log.error("Error processing VM deletion: %s", str(e))
        raise


def _restore_vm_to_vms_file(hypervisor_path: str, hypervisor: str, vm_config: dict) -> None:
    """
    Restore VM configuration to the VMs file after failed deletion.
    
    Args:
        hypervisor_path: Path to the hypervisor directory
        hypervisor: Name of the hypervisor
        vm_config: VM configuration to restore
    """
    try:
        # Construct VMs file path
        vms_file = os.path.join(os.path.dirname(hypervisor_path), f"{hypervisor}VMs")
        
        # Read current VMs file
        current_vms = []
        if os.path.exists(vms_file):
            try:
                current_vms = read_json_file(vms_file)
                if not isinstance(current_vms, list):
                    log.warning("VMs file contains non-array data, initializing as empty array")
                    current_vms = []
            except Exception as e:
                log.warning("Failed to read VMs file %s, initializing as empty: %s", vms_file, str(e))
                current_vms = []
        
        # Check if VM already exists in VMs file (prevent duplicates)
        vm_hostname = vm_config.get('hostname')
        if vm_hostname:
            for existing_vm in current_vms:
                if isinstance(existing_vm, dict) and existing_vm.get('hostname') == vm_hostname:
                    log.info("VM with hostname %s already exists in VMs file, skipping restoration", vm_hostname)
                    return
        
        # Add VM configuration back to VMs file
        current_vms.append(vm_config)
        
        # Write updated VMs file
        write_json_file(vms_file, current_vms)
        log.info("Successfully restored VM config for %s to VMs file %s", vm_hostname or 'unknown', vms_file)
        
    except Exception as e:
        log.error("Failed to restore VM configuration: %s", str(e))
        raise

def process_hypervisor(hypervisor_path: str) -> None:
    """
    Process VM configurations for a single hypervisor.
    
    This function handles the processing of VM configurations for a hypervisor,
    including creation of new VMs and deletion of removed VMs. All operations
    are protected by the engine-wide lock that is acquired at engine start.
    
    The function performs the following steps:
    1. Reads VMs configuration from <hypervisorHostname>VMs file
    2. Identifies existing VMs
    3. Processes new VM creation requests
    4. Handles VM deletions for removed configurations
    
    Args:
        hypervisor_path: Path to the hypervisor directory
    """
    try:
        # Get hypervisor name from path
        hypervisor = os.path.basename(hypervisor_path)
        
        # Read VMs file instead of nodes
        vms_file = os.path.join(os.path.dirname(hypervisor_path), f"{hypervisor}VMs")
        if not os.path.exists(vms_file):
            log.debug("No VMs file found at %s", vms_file)
            
            # Even if no VMs file exists, we should still clean up any expired status files
            cleanup_destroyed_vm_status_files(hypervisor_path)
            return
            
        nodes_config = read_json_file(vms_file)
        if not nodes_config:
            log.debug("Empty VMs configuration in %s", vms_file)
            
        # Get existing VMs and track failed VMs separately
        existing_vms = set()
        failed_vms = set()  # VMs with .error files
        for file_path in glob.glob(os.path.join(hypervisor_path, '*_*')):
            basename = os.path.basename(file_path)
            # Skip status files
            if basename.endswith('.status'):
                continue
            # Track VMs with .error files separately
            if basename.endswith('.error'):
                vm_name = basename[:-6]  # Remove '.error' suffix
                failed_vms.add(vm_name)
                existing_vms.add(vm_name)  # Also add to existing to prevent recreation
                log.debug(f"Found failed VM with .error file: {vm_name}")
            else:
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
                
        # Process VM deletions (but skip failed VMs that only have .error files)
        vms_to_delete = existing_vms - configured_vms
        log.debug(f"Existing VMs: {existing_vms}")
        log.debug(f"Configured VMs: {configured_vms}")
        log.debug(f"Failed VMs: {failed_vms}")
        log.debug(f"VMs to delete: {vms_to_delete}")
        for vm_name in vms_to_delete:
            # Skip deletion if VM only has .error file (no actual VM to delete)
            if vm_name in failed_vms:
                error_file = os.path.join(hypervisor_path, f"{vm_name}.error")
                base_file = os.path.join(hypervisor_path, vm_name)
                # Only skip if there's no base file (VM never successfully created)
                if not os.path.exists(base_file):
                    log.info(f"Skipping deletion of failed VM {vm_name} (VM never successfully created)")
                    # Clean up the .error and .status files since VM is no longer configured
                    if os.path.exists(error_file):
                        os.remove(error_file)
                        log.info(f"Removed .error file for unconfigured VM: {vm_name}")
                    status_file = os.path.join(hypervisor_path, f"{vm_name}.status")
                    if os.path.exists(status_file):
                        os.remove(status_file)
                        log.info(f"Removed .status file for unconfigured VM: {vm_name}")
                    
                    # Trigger hypervisor annotation update to reflect the removal
                    try:
                        log.info(f"Triggering hypervisor annotation update after removing failed VM: {vm_name}")
                        runner.cmd('state.orch', ['orch.dyanno_hypervisor'])
                    except Exception as e:
                        log.error(f"Failed to trigger hypervisor annotation update for {vm_name}: {str(e)}")
                    
                    continue
            log.info(f"Initiating deletion process for VM: {vm_name}")
            process_vm_deletion(hypervisor_path, vm_name)
            
        # Clean up expired status files for destroyed VMs
        cleanup_destroyed_vm_status_files(hypervisor_path)
            
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
    
    Args:
        interval: Time in seconds between engine runs (managed by salt-master)
        base_path: Base path containing hypervisor configurations
        
    Notes:
        - Lock remains if engine encounters an error
        - Admin must restart service to clear lock
        - Error-level logging used for lock issues
    """
    log.debug("Starting virtual node manager engine")
    
    if not validate_vrt_license():
        return
        
    # Attempt to acquire lock
    if not engine_lock.acquire(blocking=False):
        log.error("Another virtual node manager is already running")
        return
    
    log.debug("Virtual node manager acquired lock")
        
    try:
        # Process each hypervisor directory
        for hypervisor_path in glob.glob(os.path.join(base_path, '*')):
            if os.path.isdir(hypervisor_path):
                process_hypervisor(hypervisor_path)
                
        # Clean shutdown - release lock
        log.debug("Virtual node manager releasing lock")
        engine_lock.release()
        log.debug("Virtual node manager completed successfully")
                
    except Exception as e:
        log.error("Error in virtual node manager: %s", str(e))
        return
