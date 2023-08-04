#!/bin/bash
echo "Setting default session to gnome-classic"
cp /usr/share/accountsservice/user-templates/standard /etc/accountsservice/user-templates/
sed -i 's|Session=gnome|Session=gnome-classic|g' /etc/accountsservice/user-templates/standard
