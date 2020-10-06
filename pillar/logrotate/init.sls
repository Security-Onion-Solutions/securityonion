logrotate:
  conf: | 
    daily
    rotate 14
    missingok
    copytruncate
    nocompress
    create
    extension .log
    dateext
    dateyesterday
