#!/usr/bin/python3

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import sys
import time
import libvirt
import logging

def stop_vm(conn, vm_name, logger):
    """
    Stops the specified virtual machine if it is running.

    Parameters:
        conn (libvirt.virConnect): The libvirt connection object.
        vm_name (str): The name of the virtual machine.
        logger (logging.Logger): The logger object.

    Returns:
        libvirt.virDomain: The domain object of the VM.

    Raises:
        SystemExit: If the VM cannot be found or an error occurs.
    """
    try:
        dom = conn.lookupByName(vm_name)
        if dom.isActive():
            logger.info(f"Shutting down VM '{vm_name}'...")
            dom.shutdown()
            # Wait for the VM to shut down
            while dom.isActive():
                time.sleep(1)
            logger.info(f"VM '{vm_name}' has been stopped.")
        else:
            logger.info(f"VM '{vm_name}' is already stopped.")
        return dom
    except libvirt.libvirtError as e:
        logger.error(f"Failed to stop VM '{vm_name}': {e}")
        sys.exit(1)

def start_vm(dom, logger):
    """
    Starts the specified virtual machine.

    Parameters:
        dom (libvirt.virDomain): The domain object of the VM.
        logger (logging.Logger): The logger object.

    Raises:
        SystemExit: If the VM cannot be started.
    """
    try:
        dom.create()
        logger.info(f"VM '{dom.name()}' started successfully.")
    except libvirt.libvirtError as e:
        logger.error(f"Failed to start VM '{dom.name()}': {e}")
        sys.exit(1)
