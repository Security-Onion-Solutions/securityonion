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
    interval: Time in seconds between processing cycles (default: 30)
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
        - <vm_name>: Active VM configuration and status
        - <vm_name>_failed: Failed VM creation details
        - <vm_name>_invalidHW: Invalid hardware request details
    
    Lock Files:
        - .lock: Prevents concurrent processing of VMs
        - Contains VM name and timestamp
        - Automatically removed after processing

Notes:
    - Requires 'hvn' feature license
    - Uses hypervisor's sosmodel grain for hardware capabilities
    - Hardware allocation based on model-specific configurations
    - All created files maintain socore ownership
    - Comprehensive logging for troubleshooting
    - Lock files prevent concurrent processing

Description:
    The engine operates in the following phases:

    1. License Validation
       - Verifies 'hvn' feature is licensed
       - Prevents operation if license is invalid

    2. Configuration Processing
       - Reads nodes file from each hypervisor directory
       - Validates configuration parameters
       - Compares against existing VM tracking files

    3. Hardware Allocation
       - Retrieves hypervisor model from grains cache
       - Loads model-specific hardware capabilities
       - Validates hardware requests against model limits
       - Converts hardware indices to PCI IDs
       - Ensures proper type handling for hardware indices
       - Creates state tracking files with socore ownership

    4. VM Provisioning
       - Creates lock file to prevent concurrent operations
       - Executes so-salt-cloud with validated configuration
       - Handles network setup (static/DHCP)
       - Configures hardware passthrough with converted PCI IDs
       - Updates VM state tracking
       - Removes lock file after completion

Exit Codes:
    0: Success
    1: Invalid license
    2: Configuration error
    3: Hardware allocation failure
    4: VM provisioning failure
    5: Invalid hardware request

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

def create_lock_file(hypervisor_path: str, vm_name: str) -> bool:
    """Create .lock file for VM processing."""
    lock_file = os.path.join(hypervisor_path, '.lock')
    try:
        if os.path.exists(lock_file):
            log.warning("Lock file already exists at %s", lock_file)
            return False
        write_json_file(lock_file, {
            'vm': vm_name,
            'timestamp': datetime.now().isoformat()
        })
        return True
    except Exception as e:
        log.error("Failed to create lock file: %s", str(e))
        return False

def remove_lock_file(hypervisor_path: str) -> None:
    """Remove .lock file after processing."""
    lock_file = os.path.join(hypervisor_path, '.lock')
    try:
        if os.path.exists(lock_file):
            os.remove(lock_file)
    except Exception as e:
        log.error("Failed to remove lock file: %s", str(e))

def is_locked(hypervisor_path: str) -> bool:
    """Check if hypervisor directory is locked."""
    return os.path.exists(os.path.join(hypervisor_path, '.lock'))

def get_hypervisor_model(hypervisor: str) -> str:
    """Get sosmodel from hypervisor grains."""
    log.info(hypervisor) #MOD
    try:
        # Get cached grains using Salt runner
        grains = runner.cmd(
            'cache.grains',
            [f'{hypervisor}_*', 'glob']
        )
        log.info(grains) #MOD
        if not grains:
            raise ValueError(f"No grains found for hypervisor {hypervisor}")
            
        # Get the first minion ID that matches our hypervisor
        minion_id = next(iter(grains.keys()))
        log.info(minion_id) #MOD
        model = grains[minion_id].get('sosmodel')
        log.info(model) #MOD
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
    log.debug("Validating hardware request: %s", requested_hw)
    log.debug("Against model config: %s", model_config['hardware'])
    
    # Validate CPU
    if 'cpu' in requested_hw:
        try:
            cpu_count = int(requested_hw['cpu'])
            log.debug("Validating CPU request: %d against maximum: %d",
                     cpu_count, model_config['hardware']['cpu'])
            if cpu_count > model_config['hardware']['cpu']:
                errors['cpu'] = f"Requested {cpu_count} CPU cores exceeds maximum {model_config['hardware']['cpu']}"
        except ValueError:
            errors['cpu'] = "Invalid CPU value"

    # Validate Memory
    if 'memory' in requested_hw:
        try:
            memory = int(requested_hw['memory'])
            log.debug("Validating memory request: %dGB against maximum: %dGB",
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
                log.debug("Validating %s indices: %s", hw_type, indices)
                
                if hw_type not in model_config['hardware']:
                    log.error("Hardware type %s not found in model config", hw_type)
                    errors[hw_type] = f"No {hw_type} configuration found in model"
                    continue
                    
                available_indices = set(int(k) for k in model_config['hardware'][hw_type].keys())
                log.debug("Available %s indices: %s", hw_type, available_indices)
                
                invalid_indices = [idx for idx in indices if idx not in available_indices]
                if invalid_indices:
                    log.error("Invalid %s indices found: %s", hw_type, invalid_indices)
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

def check_hardware_availability(hypervisor_path: str, vm_name: str) -> bool:
    """Check if requested hardware is already claimed by another VM."""
    try:
        # List all VM tracking files
        files = glob.glob(os.path.join(hypervisor_path, '*_*'))
        for file_path in files:
            # Skip the VM we're checking and any failed/invalid VMs
            basename = os.path.basename(file_path)
            if basename.startswith(vm_name) or '_failed' in basename or '_invalidHW' in basename:
                continue
            
            # Check if any hardware overlaps
            vm_config = read_json_file(file_path)
            if 'hardware' in vm_config and 'allocated' in vm_config['hardware']:
                # TODO: Implement hardware conflict checking
                pass
        return True
    except Exception as e:
        log.error("Failed to check hardware availability: %s", str(e))
        return False

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
            'status': 'creating',
            'hardware': {
                'allocated': {}
            }
        }
        # Write file and set ownership
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        set_socore_ownership(file_path)
        log.debug("Successfully created VM tracking file with socore ownership")
    except Exception as e:
        log.error("Failed to create VM tracking file: %s", str(e))
        raise

def mark_vm_failed(vm_file: str, error_code: int, message: str) -> None:
    """Mark VM as failed with error details."""
    try:
        # Rename file to add _failed suffix if not already present
        if not vm_file.endswith('_failed'):
            new_file = f"{vm_file}_failed"
            os.rename(vm_file, new_file)
            vm_file = new_file

        # Update file contents
        data = read_json_file(vm_file)
        data['status'] = 'failed'
        data['error'] = {
            'code': error_code,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        write_json_file(vm_file, data)
    except Exception as e:
        log.error("Failed to mark VM as failed: %s", str(e))
        raise

def mark_invalid_hardware(hypervisor_path: str, vm_name: str, config: dict, error_details: dict) -> None:
    """Create invalid hardware tracking file with error details."""
    file_path = os.path.join(hypervisor_path, f"{vm_name}_invalidHW")
    try:
        data = {
            'config': config,
            'error': {
                'code': 5,
                'message': "Invalid hardware configuration",
                'invalid_hardware': error_details,
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

def process_vm_creation(hypervisor_path: str, vm_config: dict) -> None:
    """Process a single VM creation request."""
    # Get the actual hypervisor name (last directory in path)
    hypervisor = os.path.basename(hypervisor_path)
    vm_name = f"{vm_config['hostname']}_{vm_config['role']}"
    
    try:
        # Create lock file
        if not create_lock_file(hypervisor_path, vm_name):
            return

        # Get hypervisor model and capabilities
        model = get_hypervisor_model(hypervisor)
        model_config = load_hardware_defaults(model)

        # Validate hardware request
        is_valid, errors = validate_hardware_request(model_config, vm_config)
        if not is_valid:
            mark_invalid_hardware(hypervisor_path, vm_name, vm_config, errors)
            return

        # Check hardware availability
        if not check_hardware_availability(hypervisor_path, vm_name):
            mark_vm_failed(os.path.join(hypervisor_path, vm_name), 3, 
                         "Requested hardware is already in use")
            return

        # Create tracking file
        create_vm_tracking_file(hypervisor_path, vm_name, vm_config)

        # Build so-salt-cloud command
        log.debug("Building so-salt-cloud command for VM %s", vm_name)
        cmd = ['so-salt-cloud', '-p', f'sool9-{hypervisor}', vm_name]
        log.debug("Base command: %s", ' '.join(cmd))
        
        # Add network configuration
        if vm_config['network_mode'] == 'static4':
            log.debug("Adding static network configuration")
            cmd.extend(['--static4', '--ip4', vm_config['ip4'], '--gw4', vm_config['gw4']])
            if 'dns4' in vm_config:
                cmd.extend(['--dns4', vm_config['dns4']])
            if 'search4' in vm_config:
                cmd.extend(['--search4', vm_config['search4']])
        else:
            log.debug("Using DHCP network configuration")
            cmd.append('--dhcp4')
            
        # Add hardware configuration
        if 'cpu' in vm_config:
            log.debug("Adding CPU configuration: %s cores", vm_config['cpu'])
            cmd.extend(['-c', str(vm_config['cpu'])])
        if 'memory' in vm_config:
            memory_mib = int(vm_config['memory']) * 1024
            log.debug("Adding memory configuration: %sGB (%sMiB)", vm_config['memory'], memory_mib)
            cmd.extend(['-m', str(memory_mib)])
            
        # Add PCI devices with proper conversion
        for hw_type in ['disk', 'copper', 'sfp']:
            if hw_type in vm_config and vm_config[hw_type]:
                log.debug("Processing %s hardware configuration", hw_type)
                indices = [int(x) for x in str(vm_config[hw_type]).split(',')]
                log.debug("Requested %s indices: %s", hw_type, indices)
                for idx in indices:
                    try:
                        log.debug("Looking up PCI ID for %s index %d in model config", hw_type, idx)
                        log.debug("Model config for %s: %s", hw_type, model_config['hardware'][hw_type])
                        
                        # Convert all keys to integers for comparison
                        hw_config = {int(k): v for k, v in model_config['hardware'][hw_type].items()}
                        log.debug("Converted hardware config: %s", hw_config)
                        
                        pci_id = hw_config[idx]
                        log.debug("Found PCI ID for %s index %d: %s", hw_type, idx, pci_id)
                        converted_pci_id = convert_pci_id(pci_id)
                        log.debug("Converted PCI ID from %s to %s", pci_id, converted_pci_id)
                        cmd.extend(['-P', converted_pci_id])
                    except Exception as e:
                        log.error("Failed to process PCI ID for %s index %d: %s", hw_type, idx, str(e))
                        log.error("Hardware config keys: %s, looking for index: %s",
                                list(model_config['hardware'][hw_type].keys()), idx)
                        raise
            
        # Execute so-salt-cloud
        log.info("Executing command: %s", ' '.join(cmd))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            log.debug("Command completed successfully")
            log.debug("Command stdout: %s", result.stdout)
            if result.stderr:
                log.warning("Command stderr (non-fatal): %s", result.stderr)
        except subprocess.CalledProcessError as e:
            error_msg = f"so-salt-cloud execution failed (code {e.returncode})"
            if e.stdout:
                log.error("Command stdout: %s", e.stdout)
            if e.stderr:
                log.error("Command stderr: %s", e.stderr)
                error_msg = f"{error_msg}: {e.stderr}"
            log.error(error_msg)
            mark_vm_failed(os.path.join(hypervisor_path, vm_name), 4, error_msg)
            raise
        
        # Update tracking file status
        tracking_file = os.path.join(hypervisor_path, vm_name)
        data = read_json_file(tracking_file)
        data['status'] = 'running'
        write_json_file(tracking_file, data)
        log.info("Successfully updated VM status to running")
        
    except subprocess.CalledProcessError as e:
        error_msg = f"so-salt-cloud execution failed (code {e.returncode})"
        if e.stdout:
            log.error("Command stdout: %s", e.stdout)
        if e.stderr:
            log.error("Command stderr: %s", e.stderr)
            error_msg = f"{error_msg}: {e.stderr}"
        log.error(error_msg)
        mark_vm_failed(os.path.join(hypervisor_path, vm_name), 4, error_msg)
        raise
    except Exception as e:
        error_msg = f"VM creation failed: {str(e)}"
        log.error(error_msg)
        # If we haven't created the tracking file yet, create a failed one
        if not os.path.exists(os.path.join(hypervisor_path, vm_name)):
            mark_vm_failed(os.path.join(hypervisor_path, f"{vm_name}_failed"), 4, error_msg)
    finally:
        remove_lock_file(hypervisor_path)

def process_vm_deletion(hypervisor_path: str, vm_name: str) -> None:
    """Process a single VM deletion request."""
    try:
        if not create_lock_file(hypervisor_path, vm_name):
            return
            
        # Get the actual hypervisor name (last directory in path)
        hypervisor = os.path.basename(hypervisor_path)
        cmd = ['so-salt-cloud', '-p', f'sool9-{hypervisor}', vm_name, '-yd']
        
        log.info("Executing: %s", ' '.join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Log command output
        if result.stdout:
            log.debug("Command stdout: %s", result.stdout)
        if result.stderr:
            log.warning("Command stderr: %s", result.stderr)
            
        # Check return code
        if result.returncode != 0:
            error_msg = f"so-salt-cloud deletion failed (code {result.returncode}): {result.stderr}"
            log.error(error_msg)
            raise subprocess.CalledProcessError(
                result.returncode, cmd,
                output=result.stdout,
                stderr=result.stderr
            )
        
        # Remove VM tracking file
        vm_file = os.path.join(hypervisor_path, vm_name)
        if os.path.exists(vm_file):
            os.remove(vm_file)
            log.info("Successfully removed VM tracking file")
            
    except Exception as e:
        log.error("Error processing VM deletion: %s", str(e))
        raise
    finally:
        remove_lock_file(hypervisor_path)

def process_hypervisor(hypervisor_path: str) -> None:
    """Process VM configurations for a single hypervisor."""
    try:
        if is_locked(hypervisor_path):
            return

        # Read nodes file
        nodes_file = os.path.join(hypervisor_path, 'nodes')
        if not os.path.exists(nodes_file):
            return
            
        nodes_config = read_json_file(nodes_file)
        if not nodes_config:
            return
            
        # Get existing VMs
        existing_vms = set()
        for file_path in glob.glob(os.path.join(hypervisor_path, '*_*')):
            basename = os.path.basename(file_path)
            if not any(x in basename for x in ['_failed', '_invalidHW']):
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
                process_vm_creation(hypervisor_path, vm_config)
                
        # Process VM deletions
        for vm_name in existing_vms - configured_vms:
            process_vm_deletion(hypervisor_path, vm_name)
            
    except Exception as e:
        log.error("Failed to process hypervisor %s: %s", hypervisor_path, str(e))

def start(interval: int = DEFAULT_INTERVAL,
          base_path: str = DEFAULT_BASE_PATH) -> None:
    """
    Main engine loop.
    
    Args:
        interval: Time in seconds between processing cycles
        base_path: Base path containing hypervisor configurations
    """
    log.info("Starting virtual node manager engine")
    
    if not validate_hvn_license():
        return
    
    while True:
        try:
            # Process each hypervisor directory
            for hypervisor_path in glob.glob(os.path.join(base_path, '*')):
                if os.path.isdir(hypervisor_path):
                    process_hypervisor(hypervisor_path)
                    
        except Exception as e:
            log.error("Error in main engine loop: %s", str(e))
            
        time.sleep(interval)
