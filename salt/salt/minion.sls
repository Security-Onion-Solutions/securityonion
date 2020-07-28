#Future state for Salt minions
{% import_yaml 'salt/minion.defaults.yaml' as salt %}
{% set saltversion = salt.salt.minion.version %}


install_salt_minion:
  cmd.run:
    - name: yum versionlock delete "salt-*" && sh bootstrap-salt.sh -F -x python3 stable {{ saltversion }} && yum versionlock add "salt-*"