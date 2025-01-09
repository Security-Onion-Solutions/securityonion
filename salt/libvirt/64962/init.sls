python3_lief:
  pkg.installed:
    - name: securityonion-python3-lief

so-fix-salt-ldap_script:
  file.managed:
    - name: /usr/sbin/so-fix-salt-ldap.py
    - source: salt://libvirt/64962/scripts/so-fix-salt-ldap.py
    - mode: 744

fix-salt-ldap:
  cmd.run:
    - name: /usr/sbin/so-fix-salt-ldap.py
    - require:
      - pkg: python3_lief
      - file: so-fix-salt-ldap_script
    - onchanges:
      - file: so-fix-salt-ldap_script
