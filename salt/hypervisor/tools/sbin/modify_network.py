#!/usr/bin/python3

import argparse
import guestfs
import re
import sys
import logging
import os
import ipaddress
import configparser
from io import StringIO

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

NETWORK_CONFIG_DIR = "/etc/NetworkManager/system-connections"

def validate_ip_address(ip_str, description="IP address"):
    """
    Validates that the given string is a properly formatted IPv4 address or IPv4 interface.
    """
    try:
        # Try to parse as IPv4 interface (e.g., "192.168.1.10/24")
        ipaddress.IPv4Interface(ip_str)
    except ValueError:
        try:
            # Try to parse as IPv4 address (e.g., "192.168.1.10")
            ipaddress.IPv4Address(ip_str)
        except ValueError:
            raise ValueError(f"Invalid {description}: {ip_str}")

def validate_dns_addresses(dns_str):
    """
    Validates a comma-separated list of DNS server IP addresses.
    """
    dns_list = dns_str.split(',')
    for dns in dns_list:
        dns = dns.strip()
        validate_ip_address(dns, description="DNS server address")

def validate_interface_name(interface_name):
    """
    Validates that the network interface name contains only valid characters.
    """
    if not re.match(r'^[a-zA-Z0-9_\-]+$', interface_name):
        raise ValueError(f"Invalid interface name: {interface_name}")

def update_ipv4_section(content, mode, ip=None, gateway=None, dns=None, search_domain=None):
    """
    Updates the IPv4 section of the network configuration file with either DHCP or static settings.
    """
    config = configparser.ConfigParser(strict=False)
    config.optionxform = str  # Preserve case sensitivity
    config.read_string(content)

    if 'ipv4' not in config.sections():
        # Handle missing [ipv4] section gracefully
        config.add_section('ipv4')

    if mode == "dhcp":
        config.set('ipv4', 'method', 'auto')
        # Remove static addresses, DNS settings, and search domains
        config.remove_option('ipv4', 'address1')
        config.remove_option('ipv4', 'addresses')
        config.remove_option('ipv4', 'dns')
        config.remove_option('ipv4', 'dns-search')
    elif mode == "static":
        config.set('ipv4', 'method', 'manual')
        if ip and gateway:
            config.set('ipv4', 'address1', f"{ip},{gateway}")
        else:
            raise ValueError("Both IP address and gateway are required for static configuration.")
        if dns:
            config.set('ipv4', 'dns', f"{dns};")
        else:
            config.remove_option('ipv4', 'dns')
        if search_domain:
            config.set('ipv4', 'dns-search', f"{search_domain};")
        else:
            config.remove_option('ipv4', 'dns-search')
    else:
        raise ValueError(f"Invalid mode '{mode}'. Expected 'dhcp' or 'static'.")

    # Write the updated content back to a string
    output = StringIO()
    config.write(output, space_around_delimiters=False)
    updated_content = output.getvalue()
    output.close()

    return updated_content

def modify_network_config(image_path, interface, mode, ip=None, gateway=None, dns=None, search_domain=None):
    """
    Modifies the network configuration file for the given interface inside the QCOW2 image.
    """
    # Check for write permissions to the image file
    if not os.access(image_path, os.W_OK):
        raise PermissionError(f"Write permission denied for image file: {image_path}")

    # Initialize the guestfs instance and add the image
    g = guestfs.GuestFS(python_return_dict=True)
    try:
        g.set_network(False)  # Disable network access if not needed

        # Disable SELinux relabeling
        g.selinux = False  # Correct way to disable SELinux relabeling

        g.add_drive_opts(image_path, format="qcow2")
        g.launch()
    except RuntimeError as e:
        raise RuntimeError(f"Failed to initialize GuestFS or launch appliance: {e}")

    try:
        # Detect and mount the operating system
        os_list = g.inspect_os()
        if not os_list:
            raise RuntimeError(f"Unable to find any OS in {image_path}.")

        root_fs = os_list[0]
        try:
            g.mount(root_fs, "/")
        except RuntimeError as e:
            raise RuntimeError(f"Failed to mount the filesystem: {e}")

        # Check if NetworkManager configuration directory exists
        if not g.is_dir(NETWORK_CONFIG_DIR):
            raise FileNotFoundError(f"NetworkManager configuration directory not found in the image at {NETWORK_CONFIG_DIR}.")

        # Path to the network configuration file for the given interface
        config_file_path = f"{NETWORK_CONFIG_DIR}/{interface}.nmconnection"

        # Read the current configuration file
        try:
            file_content = g.read_file(config_file_path)
            current_content = file_content.decode('utf-8')
        except RuntimeError:
            raise FileNotFoundError(f"Configuration file for {interface} not found at {config_file_path}.")
        except UnicodeDecodeError:
            raise ValueError(f"Failed to decode the configuration file for {interface}.")

        # Update the content based on the provided arguments
        updated_content = update_ipv4_section(current_content, mode, ip, gateway, dns, search_domain)

        # Write the updated content back to the configuration file
        try:
            g.write(config_file_path, updated_content.encode('utf-8'))
        except RuntimeError as e:
            raise IOError(f"Failed to write updated configuration to {config_file_path}: {e}")

        logger.info(f"Updated {interface} network configuration in {image_path} using {mode.upper()} mode.")

    except Exception as e:
        raise e
    finally:
        g.umount_all()
        g.close()

def parse_arguments():
    """
    Parses command-line arguments for the script.
    """
    parser = argparse.ArgumentParser(description="Modify IPv4 settings in a QCOW2 image for a specified network interface.")
    parser.add_argument("-I", "--image", required=True, help="Path to the QCOW2 image.")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to modify (e.g., eth0).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dhcp", action="store_true", help="Configure interface for DHCP (IPv4).")
    group.add_argument("--static4", action="store_true", help="Configure interface for static IPv4 settings.")
    parser.add_argument("--ip4", help="IPv4 address (e.g., 192.168.1.10/24). Required for static IPv4 configuration.")
    parser.add_argument("--gw4", help="IPv4 gateway (e.g., 192.168.1.1). Required for static IPv4 configuration.")
    parser.add_argument("--dns4", help="Comma-separated list of IPv4 DNS servers (e.g., 8.8.8.8,8.8.4.4).")
    parser.add_argument("--search4", help="DNS search domain for IPv4.")

    args = parser.parse_args()

    # Validate arguments
    if args.static4:
        if not args.ip4 or not args.gw4:
            parser.error("Both --ip4 and --gw4 are required for static IPv4 configuration.")
    return args

def main():
    """
    Main entry point for the script.
    """
    try:
        args = parse_arguments()

        validate_interface_name(args.interface)

        # Validate mode
        if args.dhcp:
            mode = "dhcp"
        elif args.static4:
            mode = "static"
            if not args.ip4 or not args.gw4:
                raise ValueError("Both --ip4 and --gw4 are required for static IPv4 configuration.")
            # Validate IP addresses
            validate_ip_address(args.ip4, description="IPv4 address")
            validate_ip_address(args.gw4, description="IPv4 gateway")
            if args.dns4:
                validate_dns_addresses(args.dns4)
        else:
            raise ValueError("Either --dhcp or --static4 must be specified.")

        # Modify the network configuration inside the image
        modify_network_config(args.image, args.interface, mode, args.ip4, args.gw4, args.dns4, args.search4)

    except KeyboardInterrupt:
        logger.error("Operation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
