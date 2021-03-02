{%- set ES = salt['pillar.get']('manager:mainip', '') -%}
# Wait for ElasticSearch to come up, so that we can query for version infromation
echo -n "Waiting for ElasticSearch..."
COUNT=0
ELASTICSEARCH_CONNECTED="no"
while [[ "$COUNT" -le 30 ]]; do
  curl --output /dev/null --silent --head --fail -L https://{{ ES }}:9200
  if [ $? -eq 0 ]; then
    ELASTICSEARCH_CONNECTED="yes"
    echo "connected!"
    break
  else
    ((COUNT+=1))
    sleep 1
    echo -n "."
  fi
done
if [ "$ELASTICSEARCH_CONNECTED" == "no" ]; then
  echo
  echo -e "Connection attempt timed out.  Unable to connect to ElasticSearch.  \nPlease try: \n  -checking log(s) in /var/log/elasticsearch/\n  -running 'sudo docker ps' \n  -running 'sudo so-elastic-restart'"
  echo

  exit
fi

# Make sure Kibana is running
MAX_WAIT=240

# Check to see if Kibana is available
wait_step=0
  until curl -s -XGET -L http://{{ ES }}:5601 > /dev/null ; do
  wait_step=$(( ${wait_step} + 1 ))
  echo "Waiting on Kibana...Attempt #$wait_step"
	  if [ ${wait_step} -gt ${MAX_WAIT} ]; then
			  echo "ERROR: Kibana not available for more than ${MAX_WAIT} seconds."
			  exit 5
	  fi
		  sleep 1s;
  done


# Apply Kibana template
  echo
  echo "Applying Kibana template..."
  curl -s -XPUT -L http://{{ ES }}:9200/_template/kibana \
       -H 'Content-Type: application/json' \
       -d'{"index_patterns" : ".kibana", "settings": { "number_of_shards" : 1, "number_of_replicas" : 0 }, "mappings" : { "search": {"properties": {"hits": {"type": "integer"}, "version": {"type": "integer"}}}}}'
  echo

  curl -s -XPUT -L "{{ ES }}:9200/.kibana/_settings" \
       -H 'Content-Type: application/json' \
       -d'{"index" : {"number_of_replicas" : 0}}'
  echo
