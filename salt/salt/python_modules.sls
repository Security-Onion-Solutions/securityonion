docker_module_package:
  file.recurse:
    - name: /opt/so/conf/salt/module_packages/docker
    - source: salt://salt/module_packages/docker
    - clean: True
    - makedirs: True

docker_python_module_install:
  cmd.run:
    - name: /opt/saltstack/salt/bin/python3.10 -m pip install docker --no-index --find-links=/opt/so/conf/salt/module_packages/docker/ --upgrade
    - onchanges:
      - file: docker_module_package
