#!/usr/bin/env python3

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import os
import sys
import time
import yaml

lockFile = "/tmp/so-yaml.lock"


def showUsage(args):
    print('Usage: {} <COMMAND> <YAML_FILE> [ARGS...]'.format(sys.argv[0]))
    print('  General commands:')
    print('    remove         - Removes a yaml key, if it exists. Requires KEY arg.')
    print('    help           - Prints this usage information.')
    print('')
    print('  Where:')
    print('   YAML_FILE       - Path to the file that will be modified. Ex: /opt/so/conf/service/conf.yaml')
    print('   KEY             - YAML key, does not support \' or " characters at this time. Ex: level1.level2')
    sys.exit(1)


def loadYaml(filename):
    file = open(filename, "r")
    content = file.read()
    return yaml.safe_load(content)


def writeYaml(filename, content):
    file = open(filename, "w")
    return yaml.dump(content, file)


def removeKey(content, key):
    pieces = key.split(".", 1)
    if len(pieces) > 1:
        removeKey(content[pieces[0]], pieces[1])
    else:
        content.pop(key, None)


def remove(args):
    if len(args) != 2:
        print('Missing filename or key arg', file=sys.stderr)
        showUsage(None)
        return

    filename = args[0]
    key = args[1]

    content = loadYaml(filename)
    removeKey(content, key)
    writeYaml(filename, content)

    return 0


def main():
    args = sys.argv[1:]

    if len(args) < 1:
        showUsage(None)
        return

    commands = {
        "help": showUsage,
        "remove": remove,
    }

    code = 1

    try:
        lockAttempts = 0
        maxAttempts = 30
        while lockAttempts < maxAttempts:
            lockAttempts = lockAttempts + 1
            try:
                f = open(lockFile, "x")
                f.close()
                break
            except Exception:
                if lockAttempts == 1:
                    print("Waiting for lock file to be released from another process...")
                time.sleep(2)

        if lockAttempts == maxAttempts:
            print("Lock file (" + lockFile + ") could not be created; proceeding without lock.")

        cmd = commands.get(args[0], showUsage)
        code = cmd(args[1:])
    finally:
        if os.path.exists(lockFile):
            os.remove(lockFile)

    sys.exit(code)


if __name__ == "__main__":
    main()
