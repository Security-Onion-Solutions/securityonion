#Future state for Salt minions
{% set saltversion = salt['pillar.get']('salt:minion:version') %}

install_salt_minion:
  cmd.run:
    - name: yum versionlock delete "salt-*" && sh bootstrap-salt.sh -F -x python3 stable {{ saltversion }} && yum versionlock add "salt-*"