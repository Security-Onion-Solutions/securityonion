patch_x509_v2_state_module:
  file.replace:
    - name: /opt/saltstack/salt/lib/python3.10/site-packages/salt/states/x509_v2.py
    - pattern: 'res = __salt__\["state.single"\]\("file.managed", name, test=test, \*\*kwargs\)'
    - repl: 'res = __salt__["state.single"]("file.managed", name, test=test, concurrent=True, **kwargs)'
    - backup: .bak
