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
  request=$1
  op=$(echo "$request" | jq -r .operation)
  id=$(echo "$request" | jq -r .id)

  response=$(so-minion "-o=$op" "-m=$id")
  exit_code=$?
  if [[ exit_code -eq 0 ]]; then
    log "Successful command execution"
    $(echo "true" > "${SOC_PIPE}")
  else
    log "Unsuccessful command execution: $response ($exit_code)"
    $(echo "false" > "${SOC_PIPE}")
  fi
}

function manage_user() {
  request=$1
  op=$(echo "$request" | jq -r .operation)

  case "$op" in
    add)
      email=$(echo "$request" | jq -r .email)
      password=$(echo "$request" | jq -r .password)
      role=$(echo "$request" | jq -r .role)
      firstName=$(echo "$request" | jq -r .firstName)
      lastName=$(echo "$request" | jq -r .lastName)
      note=$(echo "$request" | jq -r .note)
      log "Performing user '$op' for user '$email' with firstname '$firstName', lastname '$lastName', note '$note' and role '$role'"
      response=$(echo "$password" | so-user "$op" --email "$email" --firstName "$firstName" --lastName "$lastName" --note "$note" --role "$role" --skip-sync)
      exit_code=$?
      ;;
    add|enable|disable|delete)
      email=$(echo "$request" | jq -r .email)
      log "Performing user '$op' for user '$email'"
      response=$(so-user "$op" --email "$email" --skip-sync)
      exit_code=$?
      ;;
    addrole|delrole)
      email=$(echo "$request" | jq -r .email)
      role=$(echo "$request" | jq -r .role)
      log "Performing '$op' for user '$email' with role '$role'"
      response=$(so-user "$op" --email "$email" --role "$role" --skip-sync)
      exit_code=$?
      ;;
    password)
      email=$(echo "$request" | jq -r .email)
      password=$(echo "$request" | jq -r .password)
      log "Performing '$op' operation for user '$email'"
      response=$(echo "$password" | so-user "$op" --email "$email" --skip-sync)
      exit_code=$?
      ;;
    profile)
      email=$(echo "$request" | jq -r .email)
      firstName=$(echo "$request" | jq -r .firstName)
      lastName=$(echo "$request" | jq -r .lastName)
      note=$(echo "$request" | jq -r .note)
      log "Performing '$op' update for user '$email' with firstname '$firstName', lastname '$lastName', and note '$note'"
      response=$(so-user "$op" --email "$email" --firstName "$firstName" --lastName "$lastName" --note "$note")
      exit_code=$?
      ;;
    sync)
      log "Performing '$op'"
      response=$(so-user "$op")
      exit_code=$?
      ;;
    *)
      response="Unsupported user operation: $op"
      exit_code=1
      ;;
  esac

  if [[ exit_code -eq 0 ]]; then
    log "Successful command execution"
    $(echo "true" > "${SOC_PIPE}")
  else
    log "Unsuccessful command execution: $response ($exit_code)"
    $(echo "false" > "${SOC_PIPE}")
  fi
}

function manage_salt() {
  request=$1
  op=$(echo "$request" | jq -r .operation)
  minion=$(echo "$request" | jq -r .minion)
  if [[ -s $minion ]]; then
    minion=$(cat /etc/salt/minion | grep "id:" | awk '{print $2}')
  fi

  case "$op" in
    state)
      log "Performing '$op' for '$state' on minion '$minion'"
      state=$(echo "$request" | jq -r .state)
      response=$(salt --async $minion state.apply "$state" queue=True)
      exit_code=$?
      ;;
    highstate)
      log "Performing '$op' on minion '$minion'"
      response=$(salt --async $minion state.highstate queue=True)
      exit_code=$?
      ;;
    *)
      response="Unsupported salt operation: $op"
      exit_code=1
      ;;
  esac

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
    command=$(echo "$request" | jq -r .command)
    log "Received request; command=${command}"
    case "$command" in
      list-minions)
        list_minions
        ;;
      manage-minion)
        manage_minion "${request}"
        ;;
      manage-user)
        manage_user "${request}"
        ;;
      manage-salt)
        manage_salt "${request}"
        ;;
      *)
        log "Unsupported command: $command"
        $(echo "false" > "${SOC_PIPE}")
        ;;
    esac

    # allow remote reader to get a clean reader before we try to read again on next loop
    sleep 1
  fi
done
