# -*- coding: utf-8 -*-

import logging
from time import sleep
import os
import salt.client
import re

log = logging.getLogger(__name__)
local = salt.client.LocalClient()

def start(fpa, interval=10):
    log.info("##### PILLARWATCH STARTED #####")

    try:
        # maybe change this location
        dataFile = open("/opt/so/state/pillarWatch.txt", "r+")
        df = dataFile.read()
        log.info("df: %s" % str(df))
    except FileNotFoundError:
        log.info("No previous pillarWatch data saved")

    currentValues = []

    log.info("FPA: %s" % str(fpa))
    for i in fpa:
        log.trace("files: %s" % i['files'])
        log.trace("pillar: %s" % i['pillar'])
        log.trace("action: %s" % i['action'])
        pillarFiles = i['files']
        pillar = i['pillar']
        action = i['action']

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
                    # we have found the final key in the pillar that we are looking for, get the value
                    if patternFound == len(patterns):
                        for l in df.splitlines():
                            if pillar in l:
                                previousPillarValue = l.split(":")[1]
                                log.info("%s previousPillarValue:%s" % (pillar, str(previousPillarValue)))
                        currentPillarValue = str(line.split(":")[1]).strip()
                        log.info("%s currentPillarValue: %s" % (pillar,currentPillarValue))
                        if pillar in df:
                           df =  re.sub(r"\b{}\b.*".format(pillar), pillar + ': ' + currentPillarValue, df)
                           #df = df.replace(pillar, pillar + ': ' + currentPillarValue)
                        else:
                            df = pillar + ': ' + currentPillarValue
                        log.info("df: %s" % df)
                        #currentValues.append(pillar + ":" + currentPillarValue)
                        # we have found the pillar so we dont need to loop throught the file anymore
                        break
    dataFile.seek(0)
    dataFile.write(df)
    dataFile.truncate()
    dataFile.close()
