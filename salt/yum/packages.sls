install_yum_utils:
  pkg.installed:
    - name: yum-utils

install_yum_versionlock:
  pkg.installed:
    - name: yum-plugin-versionlock
