include:
  - patch.needs_restarting

patch_os:
  pkg.uptodate:
    - name: patch_os
    - refresh: True
