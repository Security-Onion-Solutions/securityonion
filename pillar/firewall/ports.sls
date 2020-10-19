firewall:
  analyst:
    ports:
      tcp:
        - 80
        - 443
      udp:
  beats_endpoint:
    ports:
      tcp:
        - 5044
  forward_nodes:
    ports:
      tcp:
        - 443
        - 5044
        - 5644
        - 9822
      udp:
  manager:
    ports:
      tcp:
        - 1514
        - 3200
        - 3306
        - 4200
        - 5601
        - 6379
        - 7788
        - 8086
        - 8090
        - 9001
        - 9200
        - 9300
        - 9400  
        - 9500
        - 9595
        - 9696
      udp:
        - 1514
  minions:
    ports:
      tcp:
        - 3142
        - 4505
        - 4506
        - 5000
        - 8080
        - 8086
        - 55000      
  osquery_endpoint:
    ports:
      tcp:
        - 8090
  search_nodes:
    ports:
      tcp:
        - 6379
        - 9300
  wazuh_endpoint:
    ports:
      tcp:
        - 1514
      udp: 
        -1514
