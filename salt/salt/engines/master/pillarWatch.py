# -*- coding: utf-8 -*-

import logging
from time import sleep
import os
import salt.client
import re
from ast import literal_eval

log = logging.getLogger(__name__)
local = salt.client.LocalClient()

def start(fpa, interval=10):
    log.info("##### PILLARWATCH STARTED #####")

    # try to open the file that stores the previous runs data
    # if the file doesn't exist, create a blank one
    try:
        # maybe change this location
        dataFile = open("/opt/so/state/pillarWatch.txt", "r+")
    except FileNotFoundError:
        log.info("No previous pillarWatch data saved")
        dataFile = open("/opt/so/state/pillarWatch.txt", "w+")

    df = dataFile.read()
    log.info("df: %s" % str(df))

    log.info("FPA: %s" % str(fpa))
    for i in fpa:
        log.trace("files: %s" % i['files'])
        log.trace("pillar: %s" % i['pillar'])
        log.trace("action: %s" % i['actions'])
        pillarFiles = i['files']
        pillar = i['pillar']
        actions = i['actions']

        patterns = pillar.split(".")
        log.trace("pillar: %s" % pillar)
        log.trace("patterns: %s" % patterns)
        log.trace("patterns length: %i" % len(patterns))
        # this var is used to track how many times the pattern has been found in the pillar file so that we can access the proper index later
        patternFound = 0
        for pillarFile in pillarFiles:
          with open(pillarFile, "r") as file:
            log.info("checking file: %s" % pillarFile)
            for line in file:
                log.trace("line: %s" % line)
                log.trace("pillarWatch engine: looking for: %s" % patterns[patternFound])
                # since we are looping line by line through a pillar file, the next line will check if each line matches the progression of keys through the pillar
                # ex. if we are looking for the value of global.pipeline, then this will loop through the pillar file until 'global' is found, then it will look
                # for pipeline. once pipeline is found, it will record the value
                if re.search(patterns[patternFound], line):
                    log.trace("PILLARWATCH FOUND: %s" % patterns[patternFound])
                    patternFound += 1
                    # we have found the final key in the pillar that we are looking for, get the previous value then the current value
                    if patternFound == len(patterns):
                        #  at this point, df is equal to the contents of the pillarWatch file that is used to tract the previous values of the pillars
                        previousPillarValue = 'PREVIOUSPILLARVALUENOTSAVEDINDATAFILE'
                        for l in df.splitlines():
                            if pillar in l:
                                previousPillarValue = l.split(":")[1].strip()
                        log.info("%s previousPillarValue: %s" % (pillar, str(previousPillarValue)))
                        currentPillarValue = str(line.split(":")[1]).strip()
                        log.info("%s currentPillarValue: %s" % (pillar,currentPillarValue))
                        if pillar in df:
                           df =  re.sub(r"\b{}\b.*".format(pillar), pillar + ': ' + currentPillarValue, df)
                        else:
                            df += pillar + ': ' + currentPillarValue + '\n'
                        log.info("df: %s" % df)
                        # we have found the pillar so we dont need to loop throught the file anymore
                        break
        if currentPillarValue != previousPillarValue:
            log.info("cPV != pPV: %s != %s" % (currentPillarValue,previousPillarValue))
            if previousPillarValue in actions['from']:
                ACTIONS=actions['from'][previousPillarValue]['to'][currentPillarValue]
            elif '*' in actions['from']:
                # need more logic here for to and from
                ACTIONS=actions['from']['*']['to']['*']
            else:
                ACTIONS='FROM TO NOT DEFINED'
            #for f in actions:
            log.info("actions: %s" % actions['from'])
            log.info("ACTIONS: %s" % ACTIONS)
            for action in ACTIONS:
                log.info(action)
                for saltModule, args in action.items():
                    log.info(saltModule)
                    log.info(args)
               # args=list(action.values())[0]
               # log.info(args)
                    whatHappened = __salt__[saltModule](**args)
                    log.info("whatHappened: %s" % whatHappened)

    dataFile.seek(0)
    dataFile.write(df)
    dataFile.truncate()
    dataFile.close()
