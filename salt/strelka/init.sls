# Copyright 2014,2015,2016,2017,2018,2019,2020 Security Onion Solutions, LLC
#
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
{%- set MASTER = grains['master'] %}
{%- set MASTERIP = salt['pillar.get']('static:masterip', '') %}

# Strelka config
strelkaconfdir:
  file.directory:
    - name: /opt/so/conf/strelka
    - user: 939
    - group: 939
    - makedirs: True

# Strelka logs 
strelkalogdir:
  file.directory:
    - name: /opt/so/log/strelka
    - user: 939
    - group: 939
    - makedirs: True

# Sync dynamic config to conf dir
strelkasync:
  file.recurse:
    - name: /opt/so/conf/strelka/
    - source: salt://strelka/files
    - user: 939
    - group: 939
    - template: jinja

strelkadatadir:
   file.directory:
    - name: /nsm/strelka
    - user: 939
    - group: 939
    - makedirs: True

strelkastagedir:
   file.directory:
    - name: /nsm/strelka/processed
    - user: 939
    - group: 939
    - makedirs: True


so-strelka-frontendimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-strelka-frontend:HH1.1.5

so-strelka-coordinatorimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/redis:5.0.5-alpine3.10

so-strelka-gatekeeperimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/redis:5.0.5-alpine3.10

so-strelka-backendimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-strelka-backend:HH1.1.5

so-strelka-managerimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-strelka-manager:HH1.1.5

so-strelka-backendimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-strelka-backend:HH1.1.5


strelka_coordinator:
  docker_container.running:
    - require:
      - so-strelka-coordinatorimage
    - image: docker.io/redis:5.0.5-alpine3.10
    - name: so-strelka-coordinator
    - command: redis-server --save "" --appendonly no
    - port_bindings:
      - 0.0.0.0:6380:6379

strelka_gatekeeper:
  docker_container.running:
    - require:
      - so-strelka-gatekeeperimage
    - image: docker.io/redis:5.0.5-alpine3.10
    - name: so-strelka-gatekeeper
    - command: redis-server --save "" --appendonly no --maxmemory-policy allkeys-lru
    - port_bindings:
      - 0.0.0.0:6381:6379
   
strelka_frontend:
  docker_container.running:
    - require:
      - so-strelka-frontendimage
    - image: docker.io/soshybridhunter/so-strelka-frontend:HH1.1.5 
    - binds:
      - /opt/so/conf/strelka/frontend/:/etc/strelka/:ro
      - /opt/so/log/strelka/:/var/log/strelka/:rw
    - privileged: True
    - name: so-strelka-frontend
    - command: strelka-frontend
    - port_bindings:
      - 0.0.0.0:57314:57314

strelka_backend:
  docker_container.running:
    - require:
      - so-strelka-backendimage
    - image: docker.io/soshybridhunter/so-strelka-backend:HH1.1.5
    - restart_policy: unless-stopped
    - binds:
      - /opt/so/conf/strelka/backend/:/etc/strelka/:ro
      - /opt/so/conf/strelka/backend/yara:/etc/yara/:ro
    - name: so-strelka-backend
    - command: strelka-backend

strelka_manager:
  docker_container.running:
    - require:
      - so-strelka-managerimage
    - image: docker.io/soshybridhunter/so-strelka-manager:HH1.1.5
    - binds:
      - /opt/so/conf/strelka/manager/:/etc/strelka/:ro
    - name: so-strelka-manager
    - command: strelka-manager

strelka_filestream:
  docker_container.running:
    - require:
      - so-strelka-filestreamimage
    - image: docker.io/soshybridhunter/so-strelka-filestream:HH1.1.5   
    - image: docker.io/wlambert/sfilestream:grpc
    - binds:
      - /opt/so/conf/strelka/filestream/:/etc/strelka/:ro
      - /nsm/strelka:/nsm/strelka
    - name: so-strelka-filestream
    - command: strelka-filestream
