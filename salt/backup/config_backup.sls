{% from 'backup/map.jinja' import BACKUP_MERGED %}

# Lock permissions on the backup directory
backupdir:
  file.directory:
    - name: /nsm/backup
    - user: 0
    - group: 0
    - makedirs: True
    - mode: 700

config_backup_script:
  file.managed:
    - name: /usr/sbin/so-config-backup
    - user: root
    - group: root
    - mode: 755
    - template: jinja
    - source: salt://backup/tools/sbin/so-config-backup.jinja
    - defaults:
        BACKUPLOCATIONS: {{ BACKUP_MERGED.locations }}
        DESTINATION: {{ BACKUP_MERGED.destination }}
  
# Add config backup
so_config_backup:
  cron.present:
    - name: /usr/sbin/so-config-backup > /dev/null 2>&1
    - user: root
    - minute: '1'
    - hour: '0'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'
