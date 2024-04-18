# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# -*- coding: utf-8 -*-

import logging
import re
import salt.client

log = logging.getLogger(__name__)
local = salt.client.LocalClient()

def start(fpa, interval=10):
    log.info("pillarWatch engine: started")

    # try to open the file that stores the previous runs data
    # if the file doesn't exist, create a blank one
    try:
        # maybe change this location
        dataFile = open("/opt/so/state/pillarWatch.txt", "r+")
    except FileNotFoundError:
        log.warn("pillarWatch engine: No previous pillarWatch data saved")
        dataFile = open("/opt/so/state/pillarWatch.txt", "w+")

    df = dataFile.read()
    for i in fpa:
        log.trace("pillarWatch engine: files: %s" % i['files'])
        log.trace("pillarWatch engine: pillar: %s" % i['pillar'])
        log.trace("pillarWatch engine: actions: %s" % i['actions'])
        pillarFiles = i['files']
        pillar = i['pillar']
        actions = i['actions']
        # these are the keys that we are going to look for as we traverse the pillarFiles
        patterns = pillar.split(".")
        # this var is used to track how many times the pattern has been found in the pillar file so that we can access the proper index later
        patternFound = 0
        for pillarFile in pillarFiles:
          with open(pillarFile, "r") as file:
            log.info("pillarWatch engine: checking file: %s" % pillarFile)
            for line in file:
                log.trace("pillarWatch engine: inspecting line: %s in file: %s" % (line, file))
                log.trace("pillarWatch engine: looking for: %s" % patterns[patternFound])
                # since we are looping line by line through a pillar file, the next line will check if each line matches the progression of keys through the pillar
                # ex. if we are looking for the value of global.pipeline, then this will loop through the pillar file until 'global' is found, then it will look
                # for pipeline. once pipeline is found, it will record the value
                if re.search(patterns[patternFound] + ':', line):
                    # strip the newline because it makes the logs u-g-l-y
                    log.info("pillarWatch engine: found: %s" % line.strip('\n'))
                    patternFound += 1
                    # we have found the final key in the pillar that we are looking for, get the previous value then the current value
                    if patternFound == len(patterns):
                        #  at this point, df is equal to the contents of the pillarWatch file that is used to tract the previous values of the pillars
                        previousPillarValue = 'PREVIOUSPILLARVALUENOTSAVEDINDATAFILE'
                        # check the contents of the dataFile that stores the previousPillarValue(s).
                        # find if the pillar we are checking for changes has previously been saved. if so, grab it's prior value
                        for l in df.splitlines():
                            if pillar in l:
                                previousPillarValue = str(l.split(":")[1].strip())
                        log.info("pillarWatch engine: %s previousPillarValue: %s" % (pillar, previousPillarValue))
                        currentPillarValue = str(line.split(":")[1]).strip()
                        log.info("pillarWatch engine: %s currentPillarValue: %s" % (pillar, currentPillarValue))
                        # if the pillar we are checking for changes has been defined in the dataFile,
                        # replace the previousPillarValue with the currentPillarValue. if it isn't in there, append it.
                        if pillar in df:
                           df =  re.sub(r"\b{}\b.*".format(pillar), pillar + ': ' + currentPillarValue, df)
                        else:
                            df += pillar + ': ' + currentPillarValue + '\n'
                        log.trace("pillarWatch engine: df: %s" % df)
                        # we have found the pillar so we dont need to loop throught the file anymore
                        break
        # if the pillar value changed, then we find what actions we should take
        log.info("pillarWatch engine: checking if currentPillarValue != previousPillarValue")
        log.info("pillarWatch engine: %s currentPillarValue: %s" % (pillar, currentPillarValue))
        log.info("pillarWatch engine: %s previousPillarValue: %s" % (pillar, previousPillarValue))
        if currentPillarValue != previousPillarValue:
            log.info("pillarWatch engine: currentPillarValue != previousPillarValue: %s != %s" % (currentPillarValue, previousPillarValue))
            # check if the previous pillar value is defined in the pillar from -> to actions
            if previousPillarValue in actions['from']:
                # check if the new / current pillar value is defined under to
                if currentPillarValue in actions['from'][previousPillarValue]['to']:
                    ACTIONS=actions['from'][previousPillarValue]['to'][currentPillarValue]
                # if the new / current pillar value isn't defined under to, is there a wildcard defined
                elif '*' in actions['from'][previousPillarValue]['to']:
                    ACTIONS=actions['from'][previousPillarValue]['to']['*']
                # no action was defined for us to take when we see the pillar change
                else:
                    ACTIONS='NO DEFINED ACTION FOR US TO TAKE'
            # if the previous pillar wasn't defined in the actions from, is there a wildcard defined for the pillar that we are changing from
            elif '*' in actions['from']:
                # is the new pillar value defined for the wildcard match
                if currentPillarValue in actions['from']['*']['to']:
                    ACTIONS=actions['from']['*']['to'][currentPillarValue]
                # if the new pillar doesn't have an action, was a wildcard defined
                elif '*' in actions['from']['*']['to']:
                # need more logic here for to and from
                    ACTIONS=actions['from']['*']['to']['*']
                else:
                    ACTIONS='NO DEFINED ACTION FOR US TO TAKE'
            # a match for the previous pillar wasn't defined in the action in either the form of a direct match or wildcard
            else:
                ACTIONS='NO DEFINED ACTION FOR US TO TAKE'
            log.info("pillarWatch engine: actions: %s" % actions['from'])
            log.info("pillarWatch engine: ACTIONS: %s" % ACTIONS)
            for action in ACTIONS:
                log.info("pillarWatch engine: action: %s" % action)
                for saltModule, args in action.items():
                    log.info("pillarWatch engine: saltModule: %s" % saltModule)
                    log.info("pillarWatch engine: args: %s" % args)
                    actionReturn = __salt__[saltModule](**args)
                    log.info("pillarWatch engine: actionReturn: %s" % actionReturn)

    dataFile.seek(0)
    dataFile.write(df)
    dataFile.truncate()
    dataFile.close()
