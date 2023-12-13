import json
import os
import sys


def checkSupportedType(meta, artifact_type):
    if artifact_type not in meta['supportedTypes']:
        sys.exit(126)
    else:
        return True


def verifyNonEmptyListValue(conf, key):
    if key not in conf or not isinstance(conf[key], list) or len(conf[key]) == 0:
        sys.exit(126)


def parseArtifact(artifact):
    data = json.loads(artifact)
    return data


def loadMetadata(file):
    dir = os.path.dirname(os.path.realpath(file))
    filename = os.path.realpath(file).rsplit('/', 1)[1].split('.')[0]
    with open(str(dir + "/" + filename + ".json"), "r") as metafile:
        return json.load(metafile)


def loadConfig(path):
    import yaml
    with open(str(path), "r") as conffile:
        return yaml.safe_load(conffile)
