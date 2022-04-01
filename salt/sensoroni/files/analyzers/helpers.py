import os
import json
import inspect

def checkSupportedType(meta, artifact_type):
    if artifact_type not in meta['supportedTypes']:
        sys.exit("No supported type detected!")
    else:
        return True


def loadData(artifact):
    request_data = json.loads(artifact)
    artifact_value = request_data['value']
    artifact_type = request_data['artifactType']
    return artifact_type, artifact_value


def loadMeta(file):
    dir = os.path.dirname(os.path.realpath(file))
    filename = os.path.realpath(file).rsplit('/', 1)[1].split('.')[0]
    with open(str(dir + "/" + filename + ".json"), "r") as metafile:
        return json.load(metafile)
    
