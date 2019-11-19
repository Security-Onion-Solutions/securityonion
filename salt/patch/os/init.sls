include:
{% if grains.os == "CentOS" %}
  - yum.packages
{% endif %}
  - patch.needs_restarting

patch_os:
  pkg.uptodate:
    - name: patch_os
    - refresh: True
