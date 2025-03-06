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
TODO: Remove passwd hash prior to release. used for development

This runner performs the initial setup required for hypervisor hosts in the Security Onion environment.
It handles downloading the Oracle Linux KVM image, setting up SSH keys for secure communication,
and creating virtual machines with cloud-init configuration.

Usage:
    salt-run setup_hypervisor.<function> [arguments]

Options:
    vm_name:     Name for the virtual machine (alphanumeric, hyphens, underscores)
    disk_size:   Size of the VM disk with unit (e.g., '220G', '300G')
    minion_id:   Salt minion ID of the hypervisor (optional)

Examples:
    # Complete environment setup (default VM 'sool9' with 220G disk)
    salt-run setup_hypervisor.setup_environment

    # Setup with custom VM name and disk size
    salt-run setup_hypervisor.setup_environment myvm 300G

    # Regenerate SSH keys
    salt-run setup_hypervisor.regenerate_ssh_keys

    # Create additional VM
    salt-run setup_hypervisor.create_vm myvm2 300G

    Notes:
        - Verifies Security Onion license
        - Downloads and validates Oracle Linux KVM image if needed
        - Generates Ed25519 SSH keys if not present
        - Creates/recreates VM based on environment changes
        - Forces hypervisor configuration via highstate after successful setup (when minion_id provided)

    Description:
        The setup process includes:
        1. License validation
        2. Oracle Linux KVM image download and checksum verification
        3. SSH key generation for secure VM access
        4. Cloud-init configuration for VM provisioning
        5. VM creation with specified disk size
        6. Hypervisor configuration via highstate (when minion_id provided and setup successful)

Exit Codes:
    Success: Returns dictionary with 'success': True and VM details
    Failure: Returns dictionary with 'success': False and error message

Logging:
    All operations are logged to:
    - Standard output (INFO level and above)
    - System log with 'setup_hypervisor' tag
"""

import base64
import hashlib
import logging
import os
import pwd
import requests
import salt.client
import salt.utils.files
import socket
import sys
import time
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
# Configure logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# Ensure we have a stream handler
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stream_handler.setFormatter(formatter)
log.addHandler(stream_handler)

def _read_and_encode_key(key_path: str) -> str:
    """Read a key file and return its base64 encoded content."""
    try:
        with salt.utils.files.fopen(key_path, 'rb') as f:
            content = f.read()
            return base64.b64encode(content).decode('utf-8')
    except Exception as e:
        log.error("Error reading key file %s: %s", key_path, str(e))
        raise

def _check_license():
    """Check if the license file exists and contains required values."""
    license_path = '/opt/so/saltstack/local/pillar/soc/license.sls'
    
    if not os.path.exists(license_path):
        log.error("LICENSE: License file not found at %s", license_path)
        return False
        
    try:
        with salt.utils.files.fopen(license_path, 'r') as f:
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
            log.error("LICENSE: 'hvn' feature not found in license")
            return False
            
        log.info("LICENSE: License validation successful")
        return True
            
    except Exception as e:
        log.error("LICENSE: Error reading license file: %s", str(e))
        return False

def _check_file_exists(path):
    """Check if a file exists and create its directory if needed."""
    if os.path.exists(path):
        return True
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return False

def _validate_image_checksum(path, expected_sha256):
    """
    Validate the checksum of an existing image file.
    Returns:
        bool: True if checksum matches, False otherwise
    """
    sha256_hash = hashlib.sha256()
    with salt.utils.files.fopen(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256_hash.update(chunk)
    
    downloaded_sha256 = sha256_hash.hexdigest()
    if downloaded_sha256 != expected_sha256:
        log.error("VALIDATE: Checksum validation failed for %s - expected: %s, got: %s",
                 path, expected_sha256, downloaded_sha256)
        return False
    
    log.info("VALIDATE: Checksum validation successful for %s", path)
    return True

# Constants
IMAGE_URL = "https://yum.oracle.com/templates/OracleLinux/OL9/u5/x86_64/OL9U5_x86_64-kvm-b253.qcow2"
IMAGE_SHA256 = "3b00bbbefc8e78dd28d9f538834fb9e2a03d5ccdc2cadf2ffd0036c0a8f02021"
IMAGE_PATH = "/nsm/libvirt/boot/OL9U5_x86_64-kvm-b253.qcow2"
MANAGER_HOSTNAME = socket.gethostname()

def _download_image():
    """
    Download and validate the Oracle Linux KVM image.
    Returns:
        bool: True if successful or file exists with valid checksum, False on error
    """
    # Check if file already exists and validate checksum
    if _check_file_exists(IMAGE_PATH):
        if _validate_image_checksum(IMAGE_PATH, IMAGE_SHA256):
            return True
        else:
            log.warning("DOWNLOAD: Existing image has invalid checksum, will re-download")
            os.unlink(IMAGE_PATH)
    
    log.info("DOWNLOAD: Starting image download process")

    try:
        # Download file
        log.info("DOWNLOAD: Downloading Oracle Linux KVM image from %s to %s", IMAGE_URL, IMAGE_PATH)
        response = requests.get(IMAGE_URL, stream=True)
        response.raise_for_status()

        # Get total file size for progress tracking
        total_size = int(response.headers.get('content-length', 0))
        downloaded_size = 0
        last_log_time = 0

        # Save file with progress logging
        with salt.utils.files.fopen(IMAGE_PATH, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded_size += len(chunk)
                
                # Log progress every second
                current_time = time.time()
                if current_time - last_log_time >= 1:
                    progress = (downloaded_size / total_size) * 100 if total_size > 0 else 0
                    log.info("DOWNLOAD: Progress - %.1f%% (%d/%d bytes)", 
                            progress, downloaded_size, total_size)
                    last_log_time = current_time

        # Validate downloaded file
        if not _validate_image_checksum(IMAGE_PATH, IMAGE_SHA256):
            os.unlink(IMAGE_PATH)
            return False

        log.info("DOWNLOAD: Successfully downloaded and validated Oracle Linux KVM image")
        return True

    except Exception as e:
        log.error("DOWNLOAD: Error downloading hypervisor image: %s", str(e))
        if os.path.exists(IMAGE_PATH):
            os.unlink(IMAGE_PATH)
        return False

def _check_ssh_keys_exist():
    """
    Check if SSH keys already exist.
    Returns:
        bool: True if both private and public keys exist, False otherwise
    """
    key_dir = '/etc/ssh/auth_keys/soqemussh'
    key_path = f'{key_dir}/id_ed25519'
    pub_key_path = f'{key_path}.pub'
    dest_dir = '/opt/so/saltstack/local/salt/libvirt/ssh/keys'
    dest_path = os.path.join(dest_dir, os.path.basename(pub_key_path))

    if os.path.exists(key_path) and os.path.exists(pub_key_path) and os.path.exists(dest_path):
        log.info("SETUP_KEYS: SSH keys already exist")
        return True
    return False

def _setup_ssh_keys():
    """
    Generate and set up SSH keys.
    Returns:
        bool: True if successful, False on error
    """
    try:
        key_dir = '/etc/ssh/auth_keys/soqemussh'
        key_path = f'{key_dir}/id_ed25519'
        pub_key_path = f'{key_path}.pub'

        # Check if keys already exist
        if _check_ssh_keys_exist():
            return True

        # Create key directories if they don't exist and set permissions
        log.info("SETUP_KEYS: Setting up SSH directory and keys")
        parent_dir = os.path.dirname(key_dir)  # /etc/ssh/auth_keys
        os.makedirs(parent_dir, exist_ok=True)
        os.chmod(parent_dir, 0o700)
        
        os.makedirs(key_dir, exist_ok=True)
        os.chmod(key_dir, 0o700)

        # Generate new ed25519 key pair
        log.info("SETUP_KEYS: Generating new SSH keys")
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize private key
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize public key and format it as an OpenSSH public key
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        public_bytes = public_bytes + b' soqemussh@salt-master\n'

        # Write the keys to files
        with salt.utils.files.fopen(key_path, 'wb') as f:
            f.write(private_bytes)

        with salt.utils.files.fopen(pub_key_path, 'wb') as f:
            f.write(public_bytes)

        # Set proper permissions
        os.chmod(key_path, 0o600)
        os.chmod(pub_key_path, 0o644)

        log.info("SETUP_KEYS: SSH keys generated successfully")

        # Copy public key to saltstack directory
        dest_dir = '/opt/so/saltstack/local/salt/libvirt/ssh/keys'
        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, os.path.basename(pub_key_path))
        
        with salt.utils.files.fopen(pub_key_path, 'rb') as src:
            with salt.utils.files.fopen(dest_path, 'wb') as dst:
                dst.write(src.read())
        
        log.info("SETUP_KEYS: Public key copied to %s", dest_dir)
        return True

    except Exception as e:
        log.error("SETUP_KEYS: Error setting up SSH keys: %s", str(e))
        return False

def _check_vm_exists(vm_name: str) -> bool:
    """
    Check if VM files already exist.
    Returns:
        bool: True if VM files exist, False otherwise
    """
    base_dir = '/opt/so/saltstack/local/salt/libvirt/images'
    vm_dir = f'{base_dir}/{vm_name}'
    vm_image = os.path.join(vm_dir, f'{vm_name}.qcow2')
    cidata_iso = os.path.join(vm_dir, f'{vm_name}-cidata.iso')
    
    required_files = [
        vm_image,
        cidata_iso,
        os.path.join(vm_dir, 'meta-data'),
        os.path.join(vm_dir, 'user-data'),
        os.path.join(vm_dir, 'network-data')
    ]
    
    exists = all(os.path.exists(f) for f in required_files)
    if exists:
        log.info("MAIN: VM %s already exists", vm_name)
    return exists

def _ensure_hypervisor_host_dir(minion_id: str = None):
    """
    Ensure the hypervisor host directory exists.
    
    This function creates the directory structure for a hypervisor host if it doesn't exist.
    The path is: /opt/so/saltstack/local/salt/hypervisor/hosts/<hypervisorHostname>
    
    Args:
        minion_id (str, optional): Salt minion ID of the hypervisor.
        
    Returns:
        bool: True if directory exists or was created successfully, False otherwise
    """
    if not minion_id:
        log.warning("HOSTDIR: No minion_id provided, skipping host directory creation")
        return True
        
    try:
        # Extract hostname from minion_id by removing role suffix (anything after first underscore)
        hostname = minion_id.split('_', 1)[0] if '_' in minion_id else minion_id
            
        # Define the directory path
        host_dir = f'/opt/so/saltstack/local/salt/hypervisor/hosts/{hostname}'
        
        # Check if directory exists and create it if it doesn't
        if os.path.exists(host_dir):
            log.info(f"HOSTDIR: Hypervisor host directory already exists: {host_dir}")
            # Create the VMs file if it doesn't exist
            vms_file = f'/opt/so/saltstack/local/salt/hypervisor/hosts/{hostname}VMs'
            if not os.path.exists(vms_file):
                with salt.utils.files.fopen(vms_file, 'w') as f:
                    f.write('[]')
                log.info(f"HOSTDIR: Created empty VMs file: {vms_file}")
                
                # Set proper ownership for the VMs file
                try:
                    socore_uid = pwd.getpwnam('socore').pw_uid
                    socore_gid = pwd.getpwnam('socore').pw_gid
                    os.chown(vms_file, socore_uid, socore_gid)
                    log.info(f"HOSTDIR: Set ownership to socore:socore for {vms_file}")
                except (KeyError, Exception) as e:
                    log.warning(f"HOSTDIR: Failed to set ownership for VMs file: {str(e)}")
            return True
            
        # Create all necessary parent directories
        os.makedirs(host_dir, exist_ok=True)
        log.info(f"HOSTDIR: Created hypervisor host directory: {host_dir}")
        
        # Create the VMs file with an empty JSON array
        vms_file = f'/opt/so/saltstack/local/salt/hypervisor/hosts/{hostname}VMs'
        with salt.utils.files.fopen(vms_file, 'w') as f:
            f.write('[]')
        log.info(f"HOSTDIR: Created empty VMs file: {vms_file}")
        
        # Set proper ownership (socore:socore)
        try:
            socore_uid = pwd.getpwnam('socore').pw_uid
            socore_gid = pwd.getpwnam('socore').pw_gid
            os.chown(host_dir, socore_uid, socore_gid)
            os.chown(vms_file, socore_uid, socore_gid)
            
            # Also set ownership for parent directories if they were just created
            parent_dir = os.path.dirname(host_dir)  # /opt/so/saltstack/local/salt/hypervisor/hosts
            if os.path.exists(parent_dir):
                os.chown(parent_dir, socore_uid, socore_gid)
                
            parent_dir = os.path.dirname(parent_dir)  # /opt/so/saltstack/local/salt/hypervisor
            if os.path.exists(parent_dir):
                os.chown(parent_dir, socore_uid, socore_gid)
                
            log.info(f"HOSTDIR: Set ownership to socore:socore for {host_dir} and {vms_file}")
        except KeyError:
            log.warning("HOSTDIR: socore user not found, skipping ownership change")
        except Exception as e:
            log.warning(f"HOSTDIR: Failed to set ownership: {str(e)}")
            
        return True
    except Exception as e:
        log.error(f"HOSTDIR: Error creating hypervisor host directory: {str(e)}")
        return False

def _apply_dyanno_hypervisor_state():
    """
    Apply the soc.dyanno.hypervisor state on the salt master.
    
    This function applies the soc.dyanno.hypervisor state on the salt master
    to update the hypervisor annotation and ensure all hypervisor host directories exist.
    
    Returns:
        bool: True if state was applied successfully, False otherwise
    """
    try:
        log.info("DYANNO: Applying soc.dyanno.hypervisor state on salt master")
        
        # Initialize the LocalClient
        local = salt.client.LocalClient()
        
        # Target the salt master to apply the soc.dyanno.hypervisor state
        target = MANAGER_HOSTNAME + '_*'
        state_result = local.cmd(target, 'state.apply', ['soc.dyanno.hypervisor', "pillar={'baseDomain': {'status': 'PreInit'}}", 'concurrent=True'], tgt_type='glob')
        log.debug(f"DYANNO: state_result: {state_result}")
        # Check if state was applied successfully
        if state_result:
            success = True
            for minion, states in state_result.items():
                if not isinstance(states, dict):
                    log.error(f"DYANNO: Unexpected result format from {minion}: {states}")
                    success = False
                    continue
                    
                for state_id, state_data in states.items():
                    if not state_data.get('result', False):
                        log.error(f"DYANNO: State {state_id} failed on {minion}: {state_data.get('comment', 'No comment')}")
                        success = False
            
            if success:
                log.info("DYANNO: Successfully applied soc.dyanno.hypervisor state")
                return True
            else:
                log.error("DYANNO: Failed to apply soc.dyanno.hypervisor state")
                return False
        else:
            log.error("DYANNO: No response from salt master when applying soc.dyanno.hypervisor state")
            return False
            
    except Exception as e:
        log.error(f"DYANNO: Error applying soc.dyanno.hypervisor state: {str(e)}")
        return False

def setup_environment(vm_name: str = 'sool9', disk_size: str = '220G', minion_id: str = None):
    """
    Main entry point to set up the hypervisor environment.

    This function orchestrates the complete setup process for a Security Onion hypervisor,
    including image management, SSH key setup, and VM creation. It ensures all components
    are properly configured and validates the environment at each step.

    Args:
        vm_name (str, optional): Name for the VM to create. Must contain only
                                alphanumeric characters, hyphens, or underscores.
                                Defaults to 'sool9'.
        disk_size (str, optional): Size of the VM disk with unit (e.g., '220G', '300G').
                                  Must end with 'G' or 'M'. Defaults to '220G'.
        minion_id (str, optional): Salt minion ID of the hypervisor. When provided,
                                  forces the hypervisor to apply its configuration via
                                  highstate after successful environment setup (image
                                  download, SSH keys, VM creation).

    Returns:
        dict: A dictionary containing:
            - success (bool): True if setup completed successfully
            - error (str): Error message if setup failed, None otherwise
            - vm_result (dict): Details about VM creation if successful

    Notes:
        - Verifies Security Onion license
        - Downloads and validates Oracle Linux KVM image if needed
        - Generates Ed25519 SSH keys if not present
        - Creates/recreates VM based on environment changes
        - Forces hypervisor configuration via highstate after successful setup
          (when minion_id is provided)

    Example:
        result = setup_environment('myvm', '300G', 'hypervisor1')
        if result['success']:
            print(f"VM created at {result['vm_result']['vm_dir']}")
        else:
            print(f"Setup failed: {result['error']}")
    """
    # Check license before proceeding
    if not _check_license():
        return {
            'success': False,
            'error': 'Invalid license or missing hvn feature',
            'vm_result': None
        }

    # Ensure hypervisor host directory exists
    if not _ensure_hypervisor_host_dir(minion_id):
        return {
            'success': False,
            'error': 'Failed to create hypervisor host directory',
            'vm_result': None
        }

    # Initialize the LocalClient
    local = salt.client.LocalClient()
    
    # Add retry logic for mine.update
    max_retries = 10
    retry_delay = 3
    mine_update_success = False
    
    for attempt in range(1, max_retries + 1):
        mine_update_result = local.cmd(minion_id, 'mine.update')
        log.debug(f"DYANNO: mine_update_result: {mine_update_result}")
        
        # Check if mine.update was successful
        if mine_update_result and all(mine_update_result.values()):
            log.info(f"DYANNO: mine.update successful on attempt {attempt}")
            mine_update_success = True
            break
        else:
            log.warning(f"DYANNO: mine.update failed on attempt {attempt}/{max_retries}, retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)
    
    if not mine_update_success:
        log.error(f"DYANNO: mine.update failed after {max_retries} attempts")

    # Apply the soc.dyanno.hypervisor state on the salt master
    if not _apply_dyanno_hypervisor_state():
        log.warning("MAIN: Failed to apply soc.dyanno.hypervisor state, continuing with setup")
        # We don't return an error here as we want to continue with the setup process

    log.info("MAIN: Starting setup_environment in setup_hypervisor runner")
    
    # Check if environment is already set up
    image_exists = _check_file_exists(IMAGE_PATH)
    image_valid = image_exists and _validate_image_checksum(IMAGE_PATH, IMAGE_SHA256)
    keys_exist = _check_ssh_keys_exist()
    vm_exists = _check_vm_exists(vm_name)

    # Track if we need to create/recreate VM
    create_vm_needed = False
    
    # Handle image setup if needed
    if not image_valid:
        log.info("MAIN: Starting image download/validation process")
        if not _download_image():
            log.error("MAIN: Image download failed")
            return {
                'success': False,
                'error': 'Image download failed',
                'vm_result': None
            }
        create_vm_needed = True
    
    # Handle SSH key setup if needed
    if not keys_exist:
        log.info("MAIN: Setting up SSH keys")
        if not _setup_ssh_keys():
            log.error("MAIN: SSH key setup failed")
            return {
                'success': False,
                'error': 'SSH key setup failed',
                'vm_result': None
            }
        create_vm_needed = True

    # Create/recreate VM if needed
    if create_vm_needed or not vm_exists:
        if vm_exists:
            log.info("MAIN: Environment changes detected, recreating VM %s", vm_name)
        else:
            log.info("MAIN: Creating new VM %s", vm_name)
        vm_result = create_vm(vm_name, disk_size)
    else:
        log.info("MAIN: No changes detected, using existing VM %s", vm_name)
        vm_result = {
            'success': True,
            'vm_dir': f'/opt/so/saltstack/local/salt/libvirt/images/{vm_name}'
        }
    
    success = vm_result.get('success', False)
    log.info("MAIN: Setup environment completed with status: %s", "SUCCESS" if success else "FAILED")
    
    # If setup was successful and we have a minion_id, run highstate
    if success and minion_id:
        log.info("MAIN: Running highstate on hypervisor %s", minion_id)
        try:
            # Initialize the LocalClient
            local = salt.client.LocalClient()
            # Run highstate on the hypervisor
            highstate_result = local.cmd(minion_id, 'state.highstate', [], timeout=1800)
            if highstate_result and minion_id in highstate_result:
                log.info("MAIN: Highstate triggered on %s", minion_id)
            else:
                log.error("MAIN: Highstate failed or timed out on %s", minion_id)
                return {
                    'success': False,
                    'error': 'Highstate failed or timed out',
                    'vm_result': None
                }
        except Exception as e:
            log.error("MAIN: Error running highstate on %s: %s", minion_id, str(e))
            return {
                'success': False,
                'error': f'Error running highstate: {str(e)}',
                'vm_result': None
            }

    return {
        'success': success,
        'error': vm_result.get('error') if not success else None,
        'vm_result': vm_result
    }

def create_vm(vm_name: str, disk_size: str = '220G'):
    """
    Creates a new virtual machine with cloud-init configuration.

    This function handles the complete VM creation process, including directory setup,
    image management, and cloud-init configuration. It ensures proper setup of the VM
    environment with all necessary components.

    Args:
        vm_name (str): Name for the VM. Must contain only alphanumeric characters,
                      hyphens, or underscores.
        disk_size (str): Size of the VM disk with unit (e.g., '220G', '300G').
                        Must end with 'G' or 'M'. Defaults to '220G'.

    Returns:
        dict: A dictionary containing:
            - success (bool): True if VM creation completed successfully
            - error (str): Error message if creation failed
            - vm_dir (str): Path to VM directory if successful

    Notes:
        - Validates Security Onion license
        - Creates cloud-init ISO for VM configuration
        - Copies and resizes base Oracle Linux image
        - Compresses final image for efficiency
        - Generates SHA256 hash for verification
        - Configures repositories and GPG keys
        - Sets up system services and storage

    Example:
        result = create_vm('myvm', '300G')
        if result['success']:
            print(f"VM created at {result['vm_dir']}")
        else:
            print(f"Creation failed: {result['error']}")
    """
    # Check license before proceeding
    if not _check_license():
        return {
            'success': False,
            'error': 'Invalid license or missing hvn feature',
        }

    try:
        # Input validation
        if not isinstance(vm_name, str) or not vm_name:
            log.error("CREATEVM: Invalid VM name")
            return {'success': False, 'error': 'Invalid VM name'}
        
        if not vm_name.isalnum() and not all(c in '-_' for c in vm_name if not c.isalnum()):
            log.error("CREATEVM: VM name must contain only alphanumeric characters, hyphens, or underscores")
            return {'success': False, 'error': 'Invalid VM name format'}

        # Validate disk size format
        if not isinstance(disk_size, str) or not disk_size.endswith(('G', 'M')):
            log.error("CREATEVM: Invalid disk size format. Must end with G or M")
            return {'success': False, 'error': 'Invalid disk size format'}
            
        try:
            size_num = int(disk_size[:-1])
            if size_num <= 0:
                raise ValueError
        except ValueError:
            log.error("CREATEVM: Invalid disk size number")
            return {'success': False, 'error': 'Invalid disk size number'}

        # Ensure base image exists
        if not os.path.exists(IMAGE_PATH):
            log.error("CREATEVM: Base image not found at %s", IMAGE_PATH)
            return {'success': False, 'error': 'Base image not found'}

        # Set up directory structure
        base_dir = '/opt/so/saltstack/local/salt/libvirt/images'
        vm_dir = f'{base_dir}/{vm_name}'
        os.makedirs(vm_dir, exist_ok=True)

        # Read the SSH public key
        pub_key_path = '/opt/so/saltstack/local/salt/libvirt/ssh/keys/id_ed25519.pub'
        try:
            with salt.utils.files.fopen(pub_key_path, 'r') as f:
                ssh_pub_key = f.read().strip()
        except Exception as e:
            log.error("CREATEVM: Failed to read SSH public key: %s", str(e))
            return {'success': False, 'error': 'Failed to read SSH public key'}

        # Read and encode GPG keys
        keys_dir = '/opt/so/saltstack/default/salt/repo/client/files/oracle/keys'
        oracle_key = _read_and_encode_key(os.path.join(keys_dir, 'RPM-GPG-KEY-oracle'))
        epel_key = _read_and_encode_key(os.path.join(keys_dir, 'RPM-GPG-KEY-EPEL-9'))
        salt_key = _read_and_encode_key(os.path.join(keys_dir, 'SALT-PROJECT-GPG-PUBKEY-2023.pub'))
        docker_key = _read_and_encode_key(os.path.join(keys_dir, 'docker.pub'))
        securityonion_key = _read_and_encode_key(os.path.join(keys_dir, 'securityonion.pub'))

        # Create meta-data
        meta_data = f"""instance-id: {vm_name}
local-hostname: {vm_name}
"""
        meta_data_path = os.path.join(vm_dir, 'meta-data')
        with salt.utils.files.fopen(meta_data_path, 'w') as f:
            f.write(meta_data)

        # Create network-data
        network_data = """network:
  config: disabled"""
        network_data_path = os.path.join(vm_dir, 'network-data')
        with salt.utils.files.fopen(network_data_path, 'w') as f:
            f.write(network_data)

        # Create user-data
        user_data = f"""#cloud-config
preserve_hostname: False
hostname: {vm_name}
fqdn: {vm_name}.local

# The passwd hash will be removed at release and is being used for debugging during development
users:
    - default
    - name: soqemussh
      groups: ['wheel']
      shell: /bin/bash
      sudo: ALL=(ALL) NOPASSWD:ALL
      lock_passwd: false
      passwd: $6$THWuTZMZhIVMGaaw$w9kozn7z7i0Y9LRVGZwN6mcZag4vMpE3hW6eCtKNHlFpL1XLcOdiIr29JyDxx3MLBXNedIqnqcj4psqCjv58d.
      ssh_authorized_keys:
        - {ssh_pub_key}

# Configure where output will go
output:
  all: ">> /var/log/cloud-init.log"

# configure interaction with ssh server
ssh_genkeytypes: ['ed25519', 'rsa']

# set timezone for VM
timezone: UTC

write_files:
  - path: /etc/yum.repos.d/securityonion.repo
    content: |
      [securityonion]
      name=Security Onion Repo
      baseurl=https://{MANAGER_HOSTNAME}/repo
      enabled=1
      gpgcheck=1
      sslverify=0
  - path: /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
    encoding: b64
    content: |
      {oracle_key}
  - path: /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9
    encoding: b64
    content: |
      {epel_key}
  - path: /etc/pki/rpm-gpg/SALT-PROJECT-GPG-PUBKEY-2023.pub
    encoding: b64
    content: |
      {salt_key}
  - path: /etc/pki/rpm-gpg/docker.pub
    encoding: b64
    content: |
      {docker_key}
  - path: /etc/pki/rpm-gpg/securityonion.pub
    encoding: b64
    content: |
      {securityonion_key}

runcmd:
  # Import GPG keys and remove repo files except securityonion.repo
  - rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
  - rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9
  - rpm --import /etc/pki/rpm-gpg/SALT-PROJECT-GPG-PUBKEY-2023.pub
  - rpm --import /etc/pki/rpm-gpg/docker.pub
  - rpm --import /etc/pki/rpm-gpg/securityonion.pub
  - for f in /etc/yum.repos.d/*.repo; do if [ "$(basename $f)" != "securityonion.repo" ]; then rm -f "$f"; fi; done
  - systemctl enable --now serial-getty@ttyS0.service
  - systemctl enable --now NetworkManager
  - systemctl enable --now qemu-guest-agent
  - growpart /dev/vda 2
  - pvresize /dev/vda2
  - lvextend -l +100%FREE /dev/vg_main/lv_root
  - xfs_growfs /dev/vg_main/lv_root
  - touch /etc/cloud/cloud-init.disabled
  - rm -f /etc/sysconfig/network-scripts/ifcfg-eth0

power_state:
  delay: "now"
  mode: poweroff
  timeout: 30
  condition: True
"""
        user_data_path = os.path.join(vm_dir, 'user-data')
        with salt.utils.files.fopen(user_data_path, 'w') as f:
            f.write(user_data)

        # Copy and resize base image
        base_image = IMAGE_PATH
        vm_image = os.path.join(vm_dir, f'{vm_name}.qcow2')
        
        # Copy base image with progress logging
        import shutil
        log.info("CREATEVM: Copying base image to %s", vm_image)
        shutil.copy2(base_image, vm_image)
        log.info("CREATEVM: Base image copy complete")
        
        # Get current image size
        import subprocess
        try:
            result = subprocess.run(['qemu-img', 'info', '--output=json', vm_image], 
                                  check=True, capture_output=True, text=True)
            import json
            info = json.loads(result.stdout)
            current_size = info.get('virtual-size', 0)
            requested_size = int(disk_size[:-1]) * (1024**3 if disk_size.endswith('G') else 1024**2)
            
            # Only resize if requested size is larger
            if requested_size > current_size:
                log.info("CREATEVM: Resizing image to %s", disk_size)
                try:
                    result = subprocess.run(['qemu-img', 'resize', '-f', 'qcow2', vm_image, disk_size], 
                                          check=True, capture_output=True, text=True)
                    log.info("CREATEVM: Image resize complete")
                except subprocess.CalledProcessError as e:
                    log.error("CREATEVM: Failed to resize image: %s", e.stderr)
                    raise
            else:
                log.info("CREATEVM: Image already at or larger than requested size")
        except subprocess.CalledProcessError as e:
            log.error("CREATEVM: Failed to get image info: %s", e.stderr)
            raise
        except json.JSONDecodeError as e:
            log.error("CREATEVM: Failed to parse image info: %s", str(e))
            raise
        
        # Compress image
        temp_image = f"{vm_image}.temp"
        log.info("CREATEVM: Compressing image")
        
        # Start compression in a subprocess
        process = subprocess.Popen(['qemu-img', 'convert', '-O', 'qcow2', '-c', vm_image, temp_image],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Monitor progress by checking output file size
        source_size = os.path.getsize(vm_image)
        last_log_time = 0
        
        while process.poll() is None:  # While compression is running
            current_time = time.time()
            if current_time - last_log_time >= 1:  # Log every second
                if os.path.exists(temp_image):
                    compressed_size = os.path.getsize(temp_image)
                    progress = (compressed_size / source_size) * 100
                    log.info("CREATEVM: Compression progress - %.1f%% (%d/%d bytes)",
                            progress, compressed_size, source_size)
                last_log_time = current_time
        
        # Check if compression completed successfully
        if process.returncode == 0:
            os.replace(temp_image, vm_image)
            log.info("CREATEVM: Image compression complete")
        else:
            error = process.stderr.read().decode('utf-8')
            log.error("CREATEVM: Failed to compress image: %s", error)
            if os.path.exists(temp_image):
                os.unlink(temp_image)
            raise subprocess.CalledProcessError(process.returncode, 'qemu-img convert', stderr=error)

        # Create cloud-init ISO
        cidata_iso = os.path.join(vm_dir, f'{vm_name}-cidata.iso')
        subprocess.run(['mkisofs', '-output', cidata_iso, '-volid', 'CIDATA', '-rock',
                       user_data_path, meta_data_path, network_data_path],
                      check=True, capture_output=True)

        # Generate SHA256 hash of the qcow2 image
        sha256_hash = hashlib.sha256()
        with salt.utils.files.fopen(vm_image, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256_hash.update(chunk)
        
        # Write hash to file
        hash_file = os.path.join(vm_dir, f'{vm_name}.sha256')
        with salt.utils.files.fopen(hash_file, 'w') as f:
            f.write(sha256_hash.hexdigest())
        
        log.info("CREATEVM: Generated SHA256 hash for %s", vm_image)

        return {
            'success': True,
            'vm_dir': vm_dir
        }

    except Exception as e:
        log.error("CREATEVM: Error creating VM: %s", str(e))
        return {'success': False, 'error': str(e)}

def regenerate_ssh_keys():
    """
    Regenerates SSH keys used for hypervisor VM access.

    This function handles the complete process of SSH key regeneration, including
    validation, cleanup of existing keys, and generation of new keys with proper
    permissions and distribution.

    Returns:
        bool: True if keys were successfully regenerated, False otherwise

    Notes:
        - Validates Security Onion license
        - Removes existing keys if present
        - Generates new Ed25519 key pair
        - Sets secure permissions (600 for private, 644 for public)
        - Distributes public key to required locations

    Description:
        The function performs these steps:
        1. Validates Security Onion license
        2. Checks for existing SSH keys
        3. Removes old keys if present
        4. Creates required directories with secure permissions
        5. Generates new Ed25519 key pair
        6. Sets appropriate file permissions
        7. Distributes public key to required locations

    Example:
        if regenerate_ssh_keys():
            print("SSH keys successfully regenerated")
        else:
            print("Failed to regenerate SSH keys")
    """
    # Check license before proceeding
    if not _check_license():
        log.error("MAIN: Invalid license or missing hvn feature")
        return False

    log.info("MAIN: Starting SSH key regeneration")
    try:
        # Verify current state
        if not _check_ssh_keys_exist():
            log.warning("MAIN: No existing SSH keys found to regenerate")
            return _setup_ssh_keys()

        # Remove existing keys
        key_dir = '/etc/ssh/auth_keys/soqemussh'
        key_path = f'{key_dir}/id_ed25519'
        pub_key_path = f'{key_path}.pub'
        dest_dir = '/opt/so/saltstack/local/salt/libvirt/ssh/keys'
        dest_path = os.path.join(dest_dir, os.path.basename(pub_key_path))

        for path in [key_path, pub_key_path, dest_path]:
            try:
                os.unlink(path)
                log.info("MAIN: Removed existing key: %s", path)
            except FileNotFoundError:
                log.warning("MAIN: Key file not found: %s", path)

        # Generate new keys
        if _setup_ssh_keys():
            log.info("MAIN: SSH keys regenerated successfully")
            return True
        
        log.error("MAIN: Failed to regenerate SSH keys")
        return False

    except Exception as e:
        log.error("MAIN: Error regenerating SSH keys: %s", str(e))
        return False
