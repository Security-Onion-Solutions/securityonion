#!py

import logging
import socket


def send(data):

  mainint = __salt__['pillar.get']('sensor:mainint', __salt__['pillar.get']('manager:mainint'))
  mainip = __salt__['grains.get']('ip_interfaces').get(mainint)[0]
  dstport = 8094

  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sent = sock.sendto(data.encode('utf-8'), (mainip, dstport))

  return sent
