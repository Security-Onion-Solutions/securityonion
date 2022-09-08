#!/bin/bash
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

PIPE_OWNER=${PIPE_OWNER:-socore}
PIPE_GROUP=${PIPE_GROUP:-socore}
SOC_PIPE=${SOC_PIPE_REQUEST:-/opt/so/conf/soc/salt.pipe}

function log() {
  echo "$(date) | $1"
}

function make_pipe() {
  path=$1

  log "Creating pipe: $path"  
  rm -f "${path}"
  mkfifo "${path}"
  chmod 0660 "${path}"
  chown ${PIPE_OWNER}:${PIPE_GROUP} "${path}"
}

make_pipe "${SOC_PIPE}"

function list_minions() {
  response=$(so-minion -o=list)
  exit_code=$?
  if [[ $exit_code -eq 0 ]]; then
    log "Successful command execution"
    $(echo "$response" > "${SOC_PIPE}")
  else
    log "Unsuccessful command execution: $exit_code"
    $(echo "false" > "${SOC_PIPE}")
  fi
}

function manage_minion() {
  command=$1
  op=$2
  minion=$3
  
  response=$(so-minion "-o=$op" "-m=$minion")
  exit_code=$?
  if [[ exit_code -eq 0 ]]; then
    log "Successful command execution"
    $(echo "true" > "${SOC_PIPE}")
  else
    log "Unsuccessful command execution: $response ($exit_code)"
    $(echo "false" > "${SOC_PIPE}")
  fi
}

while true; do
  log "Listening for request"
  request=$(cat ${SOC_PIPE})
  if [[ "$request" != "" ]]; then
    log "Received request: ${request}"
    case "$request" in
      list-minions)
        list_minions
        ;;
      manage-minion*)
        manage_minion ${request}
        ;;
      *)
        log "Unsupported command: $request"
        $(echo "false" > "${SOC_PIPE}")
    esac

    # allow remote reader to get a clean reader before we try to read again on next loop
    sleep 1
  fi
done
