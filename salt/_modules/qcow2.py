#!py

import logging
import subprocess
import shlex

log = logging.getLogger(__name__)

__virtualname__ = 'qcow2'

def __virtual__():
    return __virtualname__

def modify_network_config(image, interface, mode, ip4=None, gw4=None, dns4=None, search4=None):
    '''
    Wrapper function to call so-qcow2-modify-network

    :param image: Path to the QCOW2 image.
    :param interface: Network interface to modify (e.g., 'eth0').
    :param mode: 'dhcp4' or 'static4'.
    :param ip4: IPv4 address with CIDR notation (e.g., '192.168.1.10/24'). Required for static configuration.
    :param gw4: IPv4 gateway (e.g., '192.168.1.1'). Required for static configuration.
    :param dns4: Comma-separated list of IPv4 DNS servers (e.g., '8.8.8.8,8.8.4.4').
    :param search4: DNS search domain for IPv4.

    :return: A dictionary with the result of the script execution.

    CLI Example:

    .. code-block:: bash

        salt '*' qcow2.modify_network_config image='/nsm/libvirt/images/sool9/sool9.qcow2' interface='eth0' mode='static4' ip4='192.168.1.10/24' gw4='192.168.1.1' dns4='192.168.1.1,8.8.8.8' search4='example.local'

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
    Wrapper function to call so-kvm-modify-hardware

    :param vm_name: Name of the virtual machine to modify.
    :param cpu: Number of virtual CPUs to assign.
    :param memory: Amount of memory to assign in MiB.
    :param pci: PCI hardware ID to passthrough to the VM (e.g., '0000:00:1f.2').
    :param start: Boolean flag to start the VM after modification.

    :return: A dictionary with the result of the script execution.

    CLI Example:

    .. code-block:: bash

        salt '*' qcow2.modify_hardware_config vm_name='my_vm' cpu=4 memory=8192 pci='0000:00:1f.2' start=True

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
