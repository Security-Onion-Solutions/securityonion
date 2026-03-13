#!/usr/bin/env python3

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import os
import sys
import time
import yaml
import json

lockFile = "/tmp/so-yaml.lock"


def showUsage(args):
    print('Usage: {} <COMMAND> <YAML_FILE> [ARGS...]'.format(sys.argv[0]), file=sys.stderr)
    print('  General commands:', file=sys.stderr)
    print('    append           - Append a list item to a yaml key, if it exists and is a list. Requires KEY and LISTITEM args.', file=sys.stderr)
    print('    appendlistobject - Append an object to a yaml list key. Requires KEY and JSON_OBJECT args.', file=sys.stderr)
    print('    removelistitem   - Remove a list item from a yaml key, if it exists and is a list. Requires KEY and LISTITEM args.', file=sys.stderr)
    print('    replacelistobject  - Replace a list object based on a condition. Requires KEY, CONDITION_FIELD, CONDITION_VALUE, and JSON_OBJECT args.', file=sys.stderr)
    print('    add              - Add a new key and set its value. Fails if key already exists. Requires KEY and VALUE args.', file=sys.stderr)
    print('    get              - Displays (to stdout) the value stored in the given key. Requires KEY arg.', file=sys.stderr)
    print('    remove           - Removes a yaml key, if it exists. Requires KEY arg.', file=sys.stderr)
    print('    replace          - Replaces (or adds) a new key and set its value. Requires KEY and VALUE args.', file=sys.stderr)
    print('    help             - Prints this usage information.', file=sys.stderr)
    print('', file=sys.stderr)
    print('  Where:', file=sys.stderr)
    print('   YAML_FILE          - Path to the file that will be modified. Ex: /opt/so/conf/service/conf.yaml', file=sys.stderr)
    print('   KEY                - YAML key, does not support \' or " characters at this time. Ex: level1.level2', file=sys.stderr)
    print('   VALUE              - Value to set for a given key. Can be a literal value or file:<path> to load from a YAML file.', file=sys.stderr)
    print('   LISTITEM           - Item to append to a given key\'s list value. Can be a literal value or file:<path> to load from a YAML file.', file=sys.stderr)
    print('   JSON_OBJECT        - JSON string representing an object to append to a list.', file=sys.stderr)
    print('   CONDITION_FIELD    - Field name to match in list items (e.g., "name").', file=sys.stderr)
    print('   CONDITION_VALUE    - Value to match for the condition field.', file=sys.stderr)
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


def removeListItem(content, key, listItem):
    pieces = key.split(".", 1)
    if len(pieces) > 1:
        removeListItem(content[pieces[0]], pieces[1], listItem)
    else:
        try:
            if not isinstance(content[key], list):
                raise AttributeError("Value is not a list")
            if listItem in content[key]:
                content[key].remove(listItem)
        except (AttributeError, TypeError):
            print("The existing value for the given key is not a list. No action was taken on the file.", file=sys.stderr)
            return 1
        except KeyError:
            print("The key provided does not exist. No action was taken on the file.", file=sys.stderr)
            return 1


def convertType(value):
    if isinstance(value, str) and value.startswith("file:"):
        path = value[5:]  # Remove "file:" prefix
        if not os.path.exists(path):
            print(f"File '{path}' does not exist.", file=sys.stderr)
            sys.exit(1)
        return loadYaml(path)
    elif isinstance(value, str) and len(value) > 0 and (not value.startswith("0") or len(value) == 1):
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


def appendListObjectItem(content, key, listObject):
    pieces = key.split(".", 1)
    if len(pieces) > 1:
        appendListObjectItem(content[pieces[0]], pieces[1], listObject)
    else:
        try:
            if not isinstance(content[key], list):
                raise AttributeError("Value is not a list")
            content[key].append(listObject)
        except AttributeError:
            print("The existing value for the given key is not a list. No action was taken on the file.", file=sys.stderr)
            return 1
        except KeyError:
            print("The key provided does not exist. No action was taken on the file.", file=sys.stderr)
            return 1


def appendlistobject(args):
    if len(args) != 3:
        print('Missing filename, key arg, or JSON object to append', file=sys.stderr)
        showUsage(None)
        return 1

    filename = args[0]
    key = args[1]
    jsonString = args[2]

    try:
        # Parse the JSON string into a Python dictionary
        listObject = json.loads(jsonString)
    except json.JSONDecodeError as e:
        print(f'Invalid JSON string: {e}', file=sys.stderr)
        return 1

    # Verify that the parsed content is a dictionary (object)
    if not isinstance(listObject, dict):
        print('The JSON string must represent an object (dictionary), not an array or primitive value.', file=sys.stderr)
        return 1

    content = loadYaml(filename)
    appendListObjectItem(content, key, listObject)
    writeYaml(filename, content)

    return 0


def removelistitem(args):
    if len(args) != 3:
        print('Missing filename, key arg, or list item to remove', file=sys.stderr)
        showUsage(None)
        return 1

    filename = args[0]
    key = args[1]
    listItem = args[2]

    content = loadYaml(filename)
    removeListItem(content, key, convertType(listItem))
    writeYaml(filename, content)

    return 0


def replaceListObjectByCondition(content, key, conditionField, conditionValue, newObject):
    pieces = key.split(".", 1)
    if len(pieces) > 1:
        replaceListObjectByCondition(content[pieces[0]], pieces[1], conditionField, conditionValue, newObject)
    else:
        try:
            if not isinstance(content[key], list):
                raise AttributeError("Value is not a list")

            # Find and replace the item that matches the condition
            found = False
            for i, item in enumerate(content[key]):
                if isinstance(item, dict) and item.get(conditionField) == conditionValue:
                    content[key][i] = newObject
                    found = True
                    break

            if not found:
                print(f"No list item found with {conditionField}={conditionValue}. No action was taken on the file.", file=sys.stderr)
                return 1

        except AttributeError:
            print("The existing value for the given key is not a list. No action was taken on the file.", file=sys.stderr)
            return 1
        except KeyError:
            print("The key provided does not exist. No action was taken on the file.", file=sys.stderr)
            return 1


def replacelistobject(args):
    if len(args) != 5:
        print('Missing filename, key arg, condition field, condition value, or JSON object', file=sys.stderr)
        showUsage(None)
        return 1

    filename = args[0]
    key = args[1]
    conditionField = args[2]
    conditionValue = args[3]
    jsonString = args[4]

    try:
        # Parse the JSON string into a Python dictionary
        newObject = json.loads(jsonString)
    except json.JSONDecodeError as e:
        print(f'Invalid JSON string: {e}', file=sys.stderr)
        return 1

    # Verify that the parsed content is a dictionary (object)
    if not isinstance(newObject, dict):
        print('The JSON string must represent an object (dictionary), not an array or primitive value.', file=sys.stderr)
        return 1

    content = loadYaml(filename)
    result = replaceListObjectByCondition(content, key, conditionField, conditionValue, newObject)

    if result != 1:
        writeYaml(filename, content)

    return result if result is not None else 0


def addKey(content, key, value):
    pieces = key.split(".", 1)
    if len(pieces) > 1:
        if pieces[0] not in content or content[pieces[0]] is None:
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
        print(f"Key '{key}' not found by so-yaml.py", file=sys.stderr)
        return 2

    if isinstance(output, (dict, list)):
        print(yaml.safe_dump(output).strip())
    else:
        print(output)
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
        "appendlistobject": appendlistobject,
        "removelistitem": removelistitem,
        "replacelistobject": replacelistobject,
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
