#!/bin/bash
#
# Copyright 2014-2023 Security Onion Solutions, LLC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    INFLUXLOG=/var/log/telegraf/influxdb_size.log
 
    if [ -f "$INFLUXLOG" ]; then
        INFLUXSTATUS=$(cat $INFLUXLOG)
        echo "influxsize kbytes=$INFLUXSTATUS"
    fi
fi

exit 0
