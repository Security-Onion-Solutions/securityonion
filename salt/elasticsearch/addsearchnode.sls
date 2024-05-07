so-soc container extrahosts
seed_hosts elasticsearch.yaml
so-elasticsearch container extrahosts
so-logstash container extrahosts

          ID: elasticfleet_sbin_jinja
    Function: file.recurse
        Name: /usr/sbin
      Result: True
     Comment: Recursively updated /usr/sbin
     Started: 19:56:53.468894
    Duration: 951.706 ms
     Changes:
              ----------
              /usr/sbin/so-elastic-fleet-artifacts-url-update:
                  ----------
                  diff:
                      ---
                      +++
                      @@ -26,7 +26,7 @@
                       }

                       # Query for the current Grid Nodes that are running Logstash (which includes Fleet Nodes)
                      -LOGSTASHNODES='{"manager": {"jpp70man1": {"ip": "10.66.166.231"}}, "searchnode": {"jpp70sea1": {"ip": "10.66.166.232"}, "jpp70sea2": {"ip": "10.66.166.142"}}}'
                      +LOGSTASHNODES='{"manager": {"jpp70man1": {"ip": "10.66.166.231"}}, "searchnode": {"jpp70sea1": {"ip": "10.66.166.232"}}}'

                       # Initialize an array for new hosts from Fleet Nodes
                       declare -a NEW_LIST=()

