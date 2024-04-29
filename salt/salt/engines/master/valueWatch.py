# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# -*- coding: utf-8 -*-

import logging
import re
from pathlib import Path
import os
import glob
import json
from time import sleep

import sys

log = logging.getLogger(__name__)

import salt.client
local = salt.client.LocalClient()

def start(watched, interval=10):
    # this 20 second sleep allows enough time for the minion to reconnect during testing of the script when the salt-master is restarted
    sleep(20)
    log.info("valueWatch engine: started")
    # this dict will be used to store the files that we are watching and their modification times for the current iteration though a loop
    fileModTimesCurrent = {}
    # same as fileModTimesCurrent, but stores the previous values through the loop.
    # the combination of these two variables is used to determine if a files has changed.
    fileModTimesPrevious = {}
    #
    currentValues = {}

    def getValue(content, key):
        pieces = key.split(".", 1)
        if len(pieces) > 1:
            getValue(content[pieces[0]], pieces[1])
        else:
            #log.info("ck: %s" % content[key])
            return content[key]
            #content.pop(key, None)

    def updateModTimesCurrent(files):
        # this dict will be used to store the files that we are watching and their modification times for the current iteration though a loop
        fileModTimesCurrent.clear()
        for f in files:
            #log.warn(f)
            fileName = Path(f).name
            filePath = Path(f).parent
            if '*' in fileName:
                #log.info(fileName)
                #log.info(filePath)
                slsFiles = glob.glob(f)
                for slsFile in slsFiles:
                    #log.info(slsFile)
                    fileModTimesCurrent.update({slsFile: os.path.getmtime(slsFile)})
            else:
                fileModTimesCurrent.update({f: os.path.getmtime(f)})

    def compareFileModTimes():
        ret = []
        for f in fileModTimesCurrent:
            log.info(f)
            if f in fileModTimesPrevious:
                log.info("valueWatch engine: fileModTimesCurrent: %s" % fileModTimesCurrent[f])
                log.info("valueWatch engine: fileModTimesPrevious: %s" % fileModTimesPrevious[f])
                if fileModTimesCurrent[f] != fileModTimesPrevious[f]:
                    log.error("valueWatch engine: fileModTimesCurrent[f] != fileModTimesPrevious[f]")
                    log.error("valueWatch engine: " + str(fileModTimesCurrent[f]) + " != " + str(fileModTimesPrevious[f]))
                    ret.append(f)
        return ret

    # this will set the current value of 'value' from engines.conf and save it to the currentValues dict
    def updateCurrentValues():
                for target in targets:
                    log.info("valueWatch engine: refreshing pillars on %s" %  target)
                    refreshPillar = local.cmd(target, fun='saltutil.refresh_pillar', tgt_type=ttype)
                    log.info("valueWatch engine: pillar refresh results: %s" % refreshPillar)
                    # check if the result was True for the pillar refresh
                    # will need to add a recheck incase the minion was just temorarily unavailable
                    try:
                        if next(iter(refreshPillar.values())):
                            sleep(5)
                            # render the map file for the variable passed in from value.
                            mapRender = local.cmd(target, fun='jinja.load_map', arg=[mapFile, mainDict], tgt_type=ttype)
                            log.info("mR: %s" % mapRender)
                            currentValue = ''
                            previousValue = ''
                            mapRenderKeys = list(mapRender.keys())
                            if len(mapRenderKeys) > 0:
                                log.info(mapRenderKeys)
                                log.info("valueWatch engine: mapRender: %s" % mapRender)
                                minion = mapRenderKeys[0]
#                                if not isinstance(mapRender[minion], bool):
                                currentValue = getValue(mapRender[minion],value.split('.', 1)[1])
                                log.info("valueWatch engine: currentValue: %s: %s: %s" % (minion, value, currentValue))
                                currentValues.update({value: {minion: currentValue}})
                                # we have rendered the value so we don't need to have any more target render it
                                break
                    except StopIteration:
                        log.info("valueWatch engine: target %s did not respond or does not exist" % target)

                log.info("valueWatch engine: currentValues: %s" % currentValues)


    # run the main loop
    while True:
        log.info("valueWatch engine: checking watched files for changes")
        for v in watched:
            value = v['value']
            files = v['files']
            mapFile = v['map']
            targets = v['targets']
            ttype = v['ttype']
            actions = v['actions']

            patterns = value.split(".")
            mainDict = patterns.pop(0)

            log.info("valueWatch engine: value: %s" % value)
            # the call to this function will update fileModtimesCurrent
            updateModTimesCurrent(files)
            #log.trace("valueWatch engine: fileModTimesCurrent: %s" % fileModTimesCurrent)
            #log.trace("valueWatch engine: fileModTimesPrevious: %s" % fileModTimesPrevious)

            # compare with the previous checks file modification times
            modFilesDiff = compareFileModTimes()
            # if there were changes in the pillar files, then we need to have the minion render the map file to determine if the value changed
            if modFilesDiff:
                log.info("valueWatch engine: change in files detetected, updating currentValues: %s" % modFilesDiff)
                updateCurrentValues()
            elif value not in currentValues:
                log.info("valueWatch engine: %s not in currentValues, updating currentValues." % value)
                updateCurrentValues()
            else:
                log.info("valueWatch engine: no files changed, no update for currentValues")

        # save this iteration's values to previous so we can compare next run
            fileModTimesPrevious.update(fileModTimesCurrent)
        sleep(interval)
