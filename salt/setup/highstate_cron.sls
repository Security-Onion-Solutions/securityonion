post_setup_cron:
  cron.present:
    - name: 'PATH=$PATH:/usr/sbin salt-call state.highstate'
    - user: root
    - minute: '*/1'
    - identifier: post_setup_cron
