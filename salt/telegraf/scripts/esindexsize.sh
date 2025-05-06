#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

if curl -K /etc/telegraf/elasticsearch.config -s -k -L "https://localhost:9200/" -w "%{http_code}" -o /dev/null | grep -q '200'; then

    DATASTREAM_INFO=$(curl -K /etc/telegraf/elasticsearch.config -s -k -L "https://localhost:9200/_data_stream?format=json")
    INDICES=$(curl -K /etc/telegraf/elasticsearch.config -s -k -L "https://localhost:9200/_cat/indices?h=index,store.size&bytes=b&s=index:asc&format=json")
    INDICES_WITH_SIZE=()

    while IFS= read -r DS; do
        datastream_indices=()
        datastream=$(echo "$DS" | jq -r '.name')
        # influx doesn't like key starting with '.'
        if [[ $datastream != .* ]]; then
            while IFS= read -r DS_IDX; do
                datastream_indices+=("$DS_IDX")
            done < <(echo "$DS" | jq -r '.indices[].index_name')
            datastream_size=0

            for idx in ${datastream_indices[@]}; do
                current_index=$(echo "$INDICES" | jq -r --arg index "$idx" '.[] | select(.index == $index)["store.size"]')
                datastream_size=$(($datastream_size + $current_index))
            done
            INDICES_WITH_SIZE+=("${datastream}=${datastream_size}i")
            # echo "$datastream size is $(echo "$datastream_size" | numfmt --to iec)"
        fi
    done < <(echo "$DATASTREAM_INFO" | jq -c '.data_streams[]')

    measurement="elasticsearch_index_size "
    total=${#INDICES_WITH_SIZE[@]}
    for idxws in "${!INDICES_WITH_SIZE[@]}"; do
        if [[ $idxws -lt $(($total - 1)) ]]; then
            measurement+="${INDICES_WITH_SIZE[$idxws]},"
        else
            measurement+="${INDICES_WITH_SIZE[$idxws]}"
        fi
    done

    echo "$measurement"

fi