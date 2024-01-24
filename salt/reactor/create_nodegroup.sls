#!py

import logging
import os
import pwd

def run():
  minionid = data['id']
  nodegroup = data['data']['nodegroup']

  logging.info('reactor: create_nodegroup: nodegroup creation of %s requested by %s' % (nodegroup, minionid))
  pillar_path = os.path.join('/opt/so/saltstack/local/pillar/', nodegroup)
  uid, gid = pwd.getpwnam('socore').pw_uid, pwd.getpwnam('socore').pw_uid
  if not os.path.isdir(pillar_path):
    os.mkdir(pillar_path, 0o755)
    os.chown(pillar_path, uid, gid)

  return {}
