#!/usr/bin/env python3

# this script comes from the user nf-brentsaner located here https://github.com/saltstack/salt/issues/64962

import datetime
import grp
import os
import pathlib
import pwd
import shutil
##
import dbus  # dnf -y install python3-dbus
##
import lief  # https://pypi.org/project/lief/

salt_root = pathlib.Path('/opt/saltstack')
src_lib = pathlib.Path('/lib64/libldap.so.2')
dst_lib = salt_root.joinpath('salt', 'lib', 'libldap.so.2')

uname = 'salt'
gname = 'salt'

lib = lief.parse(str(src_lib))

sym = next((i for i in lib.imported_symbols if i.name == 'EVP_md2'), None)

if sym:
    # Get the Salt services from DBus.
    sysbus = dbus.SystemBus()
    sysd = sysbus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')
    mgr = dbus.Interface(sysd, 'org.freedesktop.systemd1.Manager')
    svcs = []
    for i in mgr.ListUnits():
        # first element is unit name.
        if not str(i[0]).startswith('salt-'):
            continue
        svc = sysbus.get_object('org.freedesktop.systemd1', object_path = mgr.GetUnit(str(i[0])))
        props = dbus.Interface(svc, dbus_interface = 'org.freedesktop.DBus.Properties')
        state = props.Get('org.freedesktop.systemd1.Unit', 'ActiveState')
        if str(state) == 'active':
            svcs.append(i[0])
    # Get the user/group
    u = pwd.getpwnam(uname)
    g = grp.getgrnam(gname)
    # Modify
    print('Modifications necessary.')
    if svcs:
        # Stop the services first.
        for sn in svcs:
            mgr.StopUnit(sn, 'replace')
    if dst_lib.exists():
        # 3.10 deprecated .utcnow().
        #dst_lib_bak = pathlib.Path(str(dst_lib) + '.bak_{0}'.format(datetime.datetime.now(datetime.UTC).timestamp()))
        dst_lib_bak = pathlib.Path(str(dst_lib) + '.bak_{0}'.format(datetime.datetime.utcnow().timestamp()))
        os.rename(dst_lib, dst_lib_bak)
        print('Destination file {0} exists; backed up to {1}.'.format(dst_lib, dst_lib_bak))
    lib.remove_dynamic_symbol(sym)
    lib.write(str(dst_lib))
    os.chown(dst_lib, u.pw_uid, g.gr_gid)
    os.chmod(dst_lib, src_lib.stat().st_mode)
    # Before we restart services, we also want to remove any python caches.
    for root, dirs, files in os.walk(salt_root):
        for f in files:
            if f.lower().endswith('.pyc'):
                fpath = os.path.join(root, f)
                os.remove(fpath)
                print('Removed file {0}'.format(fpath))
        if '__pycache__' in dirs:
            dpath = os.path.join(root, '__pycache__')
            shutil.rmtree(dpath)
            print('Removed directory {0}'.format(dpath))
    # And then start the units that were started before.
    if svcs:
        for sn in svcs:
            mgr.RestartUnit(sn, 'replace')
else:
    print('No EVP_md2 symbol found in the library. No modifications needed.')

print('Done.')
