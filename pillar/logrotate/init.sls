logrotate:
  conf: | 
    daily
    rotate 14
    missingok
    copytruncate
    compress
    create
    extension .log
    dateext
    dateyesterday