so_user_sync:
  local.cmd.run:
    - tgt: {{ data['data']['id'] }}
    - arg:
      - /usr/sbin/so-user sync
