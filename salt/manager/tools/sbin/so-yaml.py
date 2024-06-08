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
    print('Usage: {} <COMMAND> <YAML_FILE> [ARGS...]'.format(sys.argv[0]), file=sys.stderr)
    print('  General commands:', file=sys.stderr)
    print('    append         - Append a list item to a yaml key, if it exists and is a list. Requires KEY and LISTITEM args.', file=sys.stderr)
    print('    add            - Add a new key and set its value. Fails if key already exists. Requires KEY and VALUE args.', file=sys.stderr)
    print('    get            - Displays (to stdout) the value stored in the given key. Requires KEY arg.', file=sys.stderr)
    print('    remove         - Removes a yaml key, if it exists. Requires KEY arg.', file=sys.stderr)
    print('    replace        - Replaces (or adds) a new key and set its value. Requires KEY and VALUE args.', file=sys.stderr)
    print('    help           - Prints this usage information.', file=sys.stderr)
    print('', file=sys.stderr)
    print('  Where:', file=sys.stderr)
    print('   YAML_FILE       - Path to the file that will be modified. Ex: /opt/so/conf/service/conf.yaml', file=sys.stderr)
    print('   KEY             - YAML key, does not support \' or " characters at this time. Ex: level1.level2', file=sys.stderr)
    print('   VALUE           - Value to set for a given key', file=sys.stderr)
    print('   LISTITEM        - Item to append to a given key\'s list value', file=sys.stderr)
    sys.exit(1)


def loadYaml(filename):
    file = open(filename, "r")
    content = file.read()
    return yaml.safe_load(content)


def writeYaml(filename, content):
    file = open(filename, "w")
    return yaml.safe_dump(content, file)


def appendItem(content, key, listItem):
    pieces = key.split(".", 1)
    if len(pieces) > 1:
        appendItem(content[pieces[0]], pieces[1], listItem)
    else:
        try:
            content[key].append(listItem)
        except AttributeError:
            print("The existing value for the given key is not a list. No action was taken on the file.", file=sys.stderr)
            return 1
        except KeyError:
            print("The key provided does not exist. No action was taken on the file.", file=sys.stderr)
            return 1


def convertType(value):
    if isinstance(value, str) and len(value) > 0 and (not value.startswith("0") or len(value) == 1):
        if "." in value:
            try:
                value = float(value)
                return value
            except ValueError:
                pass

        try:
            value = int(value)
            return value
        except ValueError:
            pass

        lowered_value = value.lower()
        if lowered_value == "false":
            return False
        elif lowered_value == "true":
            return True
    return value


def append(args):
    if len(args) != 3:
        print('Missing filename, key arg, or list item to append', file=sys.stderr)
        showUsage(None)
        return 1

    filename = args[0]
    key = args[1]
    listItem = args[2]

    content = loadYaml(filename)
    appendItem(content, key, convertType(listItem))
    writeYaml(filename, content)

    return 0


def addKey(content, key, value):
    pieces = key.split(".", 1)
    if len(pieces) > 1:
        if not pieces[0] in content:
            content[pieces[0]] = {}
        addKey(content[pieces[0]], pieces[1], value)
    elif key in content:
        raise KeyError("key already exists")
    else:
        content[key] = value


def add(args):
    if len(args) != 3:
        print('Missing filename, key arg, and/or value', file=sys.stderr)
        showUsage(None)
        return 1

    filename = args[0]
    key = args[1]
    value = args[2]

    content = loadYaml(filename)
    addKey(content, key, convertType(value))
    writeYaml(filename, content)

    return 0


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
        return 1

    filename = args[0]
    key = args[1]

    content = loadYaml(filename)
    removeKey(content, key)
    writeYaml(filename, content)

    return 0


def replace(args):
    if len(args) != 3:
        print('Missing filename, key arg, and/or value', file=sys.stderr)
        showUsage(None)
        return 1

    filename = args[0]
    key = args[1]
    value = args[2]

    content = loadYaml(filename)
    removeKey(content, key)
    addKey(content, key, convertType(value))
    writeYaml(filename, content)

    return 0


def getKeyValue(content, key):
    pieces = key.split(".", 1)
    if len(pieces) > 1 and pieces[0] in content:
        return getKeyValue(content[pieces[0]], pieces[1])
    return content.get(key, None)


def get(args):
    if len(args) != 2:
        print('Missing filename or key arg', file=sys.stderr)
        showUsage(None)
        return 1

    filename = args[0]
    key = args[1]

    content = loadYaml(filename)
    output = getKeyValue(content, key)
    if output is None:
        print("Not found", file=sys.stderr)
        return 2

    print(yaml.safe_dump(output))
    return 0


def main():
    args = sys.argv[1:]

    if len(args) < 1:
        showUsage(None)
        return

    commands = {
        "help": showUsage,
        "add": add,
        "append": append,
        "get": get,
        "remove": remove,
        "replace": replace,
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
                    print("Waiting for lock file to be released from another process...", file=sys.stderr)
                time.sleep(2)

        if lockAttempts == maxAttempts:
            print("Lock file (" + lockFile + ") could not be created; proceeding without lock.", file=sys.stderr)

        cmd = commands.get(args[0], showUsage)
        code = cmd(args[1:])
    finally:
        if os.path.exists(lockFile):
            os.remove(lockFile)

    sys.exit(code)


if __name__ == "__main__":
    main()
