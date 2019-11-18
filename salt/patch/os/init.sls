{% if grains.os == "CentOS" %}
include:
  - yum.packages
{% endif %}

patch_os:
  pkg.uptodate:
    - name: patch_os
    - refresh: True

needs_restarting:
  module.run:
    - mine.send:
      - func: needs_restarting.check
