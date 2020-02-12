#!/bin/bash

# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if [ "$#" -lt 2 ]; then
  cat 1>&2 <<EOF
$0 compiles a BPF expression to be passed to stenotype to apply a socket filter.
Its first argument is the interface (link type is required) and all other arguments
are passed to TCPDump.

Examples:
 $0 eth0 dst port 80
 $0 eth0 udp port 53
EOF
  exit 1
fi

interface="$1"
shift
sudo tcpdump -i $interface -ddd $@ | tail -n+2 |
while read line; do
  cols=( $line )
  printf "%04x%02x%02x%08x" ${cols[0]} ${cols[1]} ${cols[2]} ${cols[3]}
done
echo ""
