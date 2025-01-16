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
This runner performs the initial setup required for hypervisor hosts in the environment.
It handles downloading the Oracle Linux KVM image, setting up SSH keys for secure
communication, and creating the initial VM.

Functions:
    setup_environment: Downloads image, sets up SSH keys, and creates initial VM
    regenerate_ssh_keys: Regenerates SSH keys for remote access
    create_vm: Creates a new VM with cloud-init configuration

The runner is typically triggered automatically when a new hypervisor minion connects,
but can also be run manually if needed.

CLI Examples:

    # Perform complete environment setup (creates VM named 'sool9' with 220G disk by default)
    salt-run setup_hypervisor.setup_environment

    # Setup with custom VM name (uses default 220G disk)
    salt-run setup_hypervisor.setup_environment myvm

    # Setup with custom VM name and disk size
    salt-run setup_hypervisor.setup_environment myvm 300G

    # Regenerate SSH keys only
    salt-run setup_hypervisor.regenerate_ssh_keys

    # Create additional VM with default disk size (220G)
    salt-run setup_hypervisor.create_vm myvm2

    # Create additional VM with custom disk size
    salt-run setup_hypervisor.create_vm myvm3 300G
"""

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
        os.path.join(vm_dir, 'user-data')
    ]
    
    exists = all(os.path.exists(f) for f in required_files)
    if exists:
        log.info("MAIN: VM %s already exists", vm_name)
    return exists

def setup_environment(vm_name: str = 'sool9', disk_size: str = '220G', minion_id: str = None):
    """
    Main entry point to set up the hypervisor environment.
    This includes downloading the base image, generating SSH keys for remote access,
    and creating the initial VM.

    Args:
        vm_name (str, optional): Name of the VM to create as part of environment setup.
                               Defaults to 'sool9'.
        disk_size (str, optional): Size of the VM disk with unit.
                                 Defaults to '220G'.

    Returns:
        dict: Dictionary containing setup status and VM creation results
    """
    # Check license before proceeding
    if not _check_license():
        return {
            'success': False,
            'error': 'Invalid license or missing hvn feature',
            'vm_result': None
        }

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
            'vm_dir': f'/opt/so/saltstack/local/salt/libvirt/images/{vm_name}',
            'commands': [
                f"virsh pool-create-as --name {vm_name} --type dir --target /opt/so/saltstack/local/salt/libvirt/images/{vm_name}",
                f"""virt-install --name {vm_name} \\
    --memory 4096 --vcpus 4 --cpu host \\
    --disk /opt/so/saltstack/local/salt/libvirt/images/{vm_name}/{vm_name}.qcow2,format=qcow2,bus=virtio \\
    --disk /opt/so/saltstack/local/salt/libvirt/images/{vm_name}/{vm_name}-cidata.iso,device=cdrom \\
    --network bridge=br0,model=virtio \\
    --os-variant=ol9.5 \\
    --import \\
    --noautoconsole"""
            ]
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
                log.info("MAIN: Highstate completed on %s", minion_id)
            else:
                log.error("MAIN: Highstate failed or timed out on %s", minion_id)
        except Exception as e:
            log.error("MAIN: Error running highstate on %s: %s", minion_id, str(e))

    return {
        'success': success,
        'error': vm_result.get('error') if not success else None,
        'vm_result': vm_result
    }

def create_vm(vm_name: str, disk_size: str = '220G'):
    """
    Create a new VM with cloud-init configuration.
    
    Args:
        vm_name (str): Name of the VM
        disk_size (str): Size of the disk with unit (default: '220G')
    
    Returns:
        dict: Dictionary containing success status and commands to run on hypervisor
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

        # Get hostname for repo configuration
        manager_hostname = socket.gethostname()

        # Create meta-data
        meta_data = f"""instance-id: {vm_name}
local-hostname: {vm_name}
"""
        meta_data_path = os.path.join(vm_dir, 'meta-data')
        with salt.utils.files.fopen(meta_data_path, 'w') as f:
            f.write(meta_data)

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
      ssh-authorized-keys:
        - {ssh_pub_key}

# Configure where output will go
output:
  all: ">> /var/log/cloud-init.log"

# configure interaction with ssh server
ssh_genkeytypes: ['ed25519', 'rsa']

# set timezone for VM
timezone: UTC

# Install QEMU guest agent. Enable and start the service
packages:
  - qemu-guest-agent

write_files:
  - path: /etc/yum.repos.d/securityonion.repo
    content: |
      [securityonion]
      name=Security Onion Repo
      baseurl=https://{manager_hostname}/repo
      enabled=1
      gpgcheck=1
      sslverify=0

runcmd:
  - systemctl enable --now qemu-guest-agent
  - systemctl enable --now serial-getty@ttyS0.service
  - systemctl enable --now NetworkManager
  - growpart /dev/vda 2
  - pvresize /dev/vda2
  - lvextend -l +100%FREE /dev/vg_main/lv_root
  - xfs_growfs /dev/vg_main/lv_root
  - touch /etc/cloud/cloud-init.disabled
  - shutdown -P now
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
                       user_data_path, meta_data_path],
                      check=True, capture_output=True)

        # Generate commands for hypervisor
        commands = [
            f"virsh pool-create-as --name {vm_name} --type dir --target {vm_dir}",
            f"""virt-install --name {vm_name} \\
    --memory 4096 --vcpus 4 --cpu host \\
    --disk {vm_image},format=qcow2,bus=virtio \\
    --disk {cidata_iso},device=cdrom \\
    --network bridge=br0,model=virtio \\
    --os-variant=ol9.5 \\
    --import \\
    --noautoconsole"""
        ]

        return {
            'success': True,
            'vm_dir': vm_dir,
            'commands': commands
        }

    except Exception as e:
        log.error("CREATEVM: Error creating VM: %s", str(e))
        return {'success': False, 'error': str(e)}

def regenerate_ssh_keys():
    """
    Regenerate SSH keys.
    Returns:
        bool: True if successful, False on error
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
