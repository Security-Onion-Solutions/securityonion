#!/usr/bin/python3

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import logging
import os 
import sys

def setup_logging(logger_name, log_file_path, log_level=logging.INFO, format_str='%(asctime)s - %(levelname)s - %(message)s'):
    """
    Sets up logging for a script.

    Parameters:
        logger_name (str): The name of the logger.
        log_file_path (str): The file path for the log file.
        log_level (int): The logging level (e.g., logging.INFO, logging.DEBUG).
        format_str (str): The format string for log messages.

    Returns:
        logging.Logger: Configured logger object.
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)

    # Create directory for log file if it doesn't exist
    log_file_dir = os.path.dirname(log_file_path)
    if log_file_dir and not os.path.exists(log_file_dir):
        try:
            os.makedirs(log_file_dir)
        except OSError as e:
            print(f"Error creating directory {log_file_dir}: {e}")
            sys.exit(1)

    # Create handlers
    c_handler = logging.StreamHandler()
    f_handler = logging.FileHandler(log_file_path)
    c_handler.setLevel(log_level)
    f_handler.setLevel(log_level)

    # Create formatter and add it to handlers
    formatter = logging.Formatter(format_str)
    c_handler.setFormatter(formatter)
    f_handler.setFormatter(formatter)

    # Add handlers to the logger if they are not already added
    if not logger.hasHandlers():
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)

    return logger
