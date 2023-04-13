include:
  - salt.minion-state-apply-test

state-apply-test:
  schedule.present:
    - name: salt-minion-state-apply-test
    - function: state.sls
    - job_args:
      - salt.minion-state-apply-test
    - minutes: 5
    - splay:
       start: 0
       end: 180

so-salt-minion-check_cron:
  cron.present:
    - name: /usr/sbin/so-salt-minion-check -q
    - identifier: so-salt-minion-check_cron
    - user: root
    - minute: '*/5'
