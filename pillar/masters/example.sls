# Example Pillar file for a master
master:
  esaccessip: 127.0.0.1
  esheap: CHANGEME
  esclustername: {{ grains.host }}
  freq: 0
  domainstats: 0
  lsheap: 1500m
  lsaccessip: 127.0.0.1
  elastalert: 1
