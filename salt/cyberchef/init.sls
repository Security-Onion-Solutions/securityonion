# Copyright 2014,2015,2016,2017,2018 Security Onion Solutions, LLC

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Create the cyberchef group
cyberchefgroup:
  group.present:
    - name: cyberchef
    - gid: 946

# Add the cyberchef user
cyberchef:
  user.present:
    - uid: 946
    - gid: 946
    - home: /opt/so/conf/cyberchef

cyberchefconfdir:
  file.directory:
    - name: /opt/so/conf/cyberchef
    - user: 946
    - group: 939
    - makedirs: True

cybercheflog:
  file.directory:
    - name: /opt/so/log/cyberchef
    - user: 946
    - group: 946
    - makedirs: True

so-cyberchefimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-cyberchef:HH1.1.3

so-cyberchef:
  docker_container.running:
    - require:
      - so-cyberchef
    - image: docker.io/soshybridhunter/so-cyberchef:HH1.1.3
    - port_bindings:
      - 0.0.0.0:9080:8080
