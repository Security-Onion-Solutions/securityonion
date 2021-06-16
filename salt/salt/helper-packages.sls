{% from 'salt/map.jinja' import PYINOTIFYPACKAGE with context%}
{% from 'salt/map.jinja' import PYTHONINSTALLER with context%}

patch_package:
  pkg.installed:
    - name: patch

pyinotify:
  {{PYTHONINSTALLER}}.installed:
    - name: {{ PYINOTIFYPACKAGE }}
