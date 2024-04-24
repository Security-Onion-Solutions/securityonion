# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# -*- coding: utf-8 -*-

import logging
import re
log = logging.getLogger(__name__)

# will need this in future versions of this engine
import salt.client
local = salt.client.LocalClient()

def start(fpa, interval=10):

    def getValue(content, key):
        pieces = key.split(".", 1)
        if len(pieces) > 1:
            getValue(content[pieces[0]], pieces[1])
        else:
            #log.info("ck: %s" % content[key])
            return content[key]
            #content.pop(key, None)

    log.info("valWatch engine: #####     checking watched values for changes     #####")

    # try to open the file that stores the previous runs data
    # if the file doesn't exist, create a blank one
    try:
        # maybe change this location
        dataFile = open("/opt/so/state/valWatch.txt", "r+")
    except FileNotFoundError:
        log.warn("valWatch engine: No previous valWatch data saved")
        dataFile = open("/opt/so/state/valWatch.txt", "w+")

    df = dataFile.read()
    for i in fpa:
        log.info("valWatch engine: i: %s" % i)
        log.trace("valWatch engine: map: %s" % i['map'])
        log.trace("valWatch engine: value: %s" % i['value'])
        log.trace("valWatch engine: targets: %s" % i['targets'])
        log.trace("valWatch engine: actions: %s" % i['actions'])
        mapFile = i['map']
        value = i['value']
        targets = i['targets']
        # target type
        ttype = i['ttype']
        actions = i['actions']
        # these are the keys that we are going to look for as we traverse the pillarFiles
        patterns = value.split(".")
        mainDict = patterns.pop(0)
       # patterns = value.split(".")
        for target in targets:
            # tell targets to render mapfile and return value split
            mapRender = local.cmd(target, fun='jinja.load_map', arg=[mapFile, mainDict], tgt_type=ttype)

            currentValue = ''
            previousValue = ''
            # this var is used to track how many times the pattern has been found in the pillar file so that we can access the proper index later
            patternFound = 0
            #with open(pillarFile, "r") as file:
            #    log.debug("pillarWatch engine: checking file: %s" % pillarFile)
            mapRenderKeys = list(mapRender.keys())
            if len(mapRenderKeys) > 0:
                log.info(mapRenderKeys)
                log.info("valWatch engine: mapRender: %s" % mapRender)
                minion = mapRenderKeys[0]
                currentValue = getValue(mapRender[minion],value.split('.', 1)[1])
                log.info("valWatch engine: currentValue: %s: %s: %s" % (minion, value, currentValue))
                for l in df.splitlines():
                    if value in l:
                        previousPillarValue = str(l.split(":")[1].strip())
                log.info("valWatch engine: previousValue: %s: %s: %s" % (minion, value, previousValue))

        '''
                for key in mapRender[minion]:
                    log.info("pillarWatch engine: inspecting key: %s in mainDict: %s" % (key, mainDict))
                    log.info("pillarWatch engine: looking for: %s" % patterns[patternFound])
                    # since we are looping line by line through a pillar file, the next line will check if each line matches the progression of keys through the pillar
                    # ex. if we are looking for the value of global.pipeline, then this will loop through the pillar file until 'global' is found, then it will look
                    # for pipeline. once pipeline is found, it will record the value
                    #if re.search(patterns[patternFound], key):
                    if patterns[patternFound] == key:
                        # strip the newline because it makes the logs u-g-l-y
                        log.info("pillarWatch engine: found: %s" % key)
                        patternFound += 1
                        # we have found the final key in the pillar that we are looking for, get the previous value then the current value
                        if patternFound == len(patterns):
                            #  at this point, df is equal to the contents of the pillarWatch file that is used to tract the previous values of the pillars
                            previousPillarValue = 'PREVIOUSPILLARVALUENOTSAVEDINDATAFILE'
                            # check the contents of the dataFile that stores the previousPillarValue(s).
                            # find if the pillar we are checking for changes has previously been saved. if so, grab it's prior value
                            for l in df.splitlines():
                                if value in l:
                                    previousPillarValue = str(l.split(":")[1].strip())
                            currentPillarValue = mapRender[minion][key]
                            log.info("pillarWatch engine: %s currentPillarValue: %s" % (value, currentPillarValue))
                            log.info("pillarWatch engine: %s previousPillarValue: %s" % (value, previousPillarValue))
                            # if the pillar we are checking for changes has been defined in the dataFile,
                            # replace the previousPillarValue with the currentPillarValue. if it isn't in there, append it.
                            if value in df:
                                df =  re.sub(r"\b{}\b.*".format(pillar), pillar + ': ' + currentPillarValue, df)
                            else:
                                df += value + ': ' + currentPillarValue + '\n'
                            log.info("pillarWatch engine: df: %s" % df)
                            # we have found the pillar so we dont need to loop through the file anymore
                            break
        # if key and value was found in the first file, then we don't want to look in
        # any more files since we use the first file as the source of truth.
        if patternFound == len(patterns):
            break
        '''


    dataFile.seek(0)
    dataFile.write(df)
    dataFile.truncate()
    dataFile.close()
