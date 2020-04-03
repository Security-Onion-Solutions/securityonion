#!py

import logging


def capstats(interval=10):

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl capstats %i'" % interval
 retval = __salt__['docker.run']('so-zeek', cmd)
 
 return retval


def check():

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl check'"
 retval = __salt__['docker.run']('so-zeek', cmd)
 
 return retval


def cleanup(all=''):

 retval = ''

 if all: 
   if all == 'all':
     cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl cleanup --all'"
   else:
     retval = 'Invalid option. zeekctl.help for options'
 else:
   cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl cleanup'"

 if not retval:
   retval = __salt__['docker.run']('so-zeek', cmd)
 return retval


def config():

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl config'"
 retval = __salt__['docker.run']('so-zeek', cmd)
 return retval


def deploy():

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl deploy'"
 retval = __salt__['docker.run']('so-zeek', cmd)
 return retval


def df():

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl df'"
 retval = __salt__['docker.run']('so-zeek', cmd)
 return retval


def diag():

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl diag'"
 retval = __salt__['docker.run']('so-zeek', cmd)
 return retval


def install(local=''):

 retval = ''

 if local:
   if local == 'local':
     cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl install --local'"
   else:
     retval = 'Invalid option. zeekctl.help for options' 
 else:
   cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl install'"
 
 if not retval:
   retval = __salt__['docker.run']('so-zeek', cmd)
 return retval


def netstats():

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl netstats'"
 retval = __salt__['docker.run']('so-zeek', cmd)
 return retval


def nodes():

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl nodes'"
 retval = __salt__['docker.run']('so-zeek', cmd)
 return retval


def restart(clean=''):

 retval = ''

 if clean:
   if clean == 'clean':
     cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl restart --clean'"
   else:
     retval = 'Invalid option. zeekctl.help for options'
 else:
   cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl restart'"
 
 if not retval:
   retval = __salt__['docker.run']('so-zeek', cmd)
 return retval


def scripts(c=''):

 retval = ''

 if c:
   if c == 'c':
     cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl scripts -c'"
   else:
     retval = 'Invalid option. zeekctl.help for options'
 else:
   cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl scripts'"

 if not retval:
   retval = __salt__['docker.run']('so-zeek', cmd)
 return retval


def start():

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl start'"
 retval = __salt__['docker.run']('so-zeek', cmd)
 return retval


def status(verbose=True):

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl status'"
 retval = __salt__['docker.run']('so-zeek', cmd)
 if not verbose:
   retval = __context__['retcode']
 logging.info('zeekctl_module: zeekctl.status retval: %s' % retval)
 return retval


def stop():

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl stop'"
 retval = __salt__['docker.run']('so-zeek', cmd)
 return retval


def top():

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl top'"
 retval = __salt__['docker.run']('so-zeek', cmd)
 return retval
