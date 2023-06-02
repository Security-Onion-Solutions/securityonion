#!/bin/bash
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

PIPE_OWNER=${PIPE_OWNER:-socore}
PIPE_GROUP=${PIPE_GROUP:-socore}
SOC_PIPE=${SOC_PIPE:-/opt/so/conf/soc/salt/pipe}
CMD_PREFIX=${CMD_PREFIX:-""}
PATH=${PATH}:/usr/sbin

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
  response=$($CMD_PREFIX so-minion -o=list)
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

  response=$($CMD_PREFIX so-minion "-o=$op" "-m=$id")
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

  max_tries=10
  tries=0
  while [[ $tries -lt $max_tries ]]; do
    case "$op" in
      add)
        email=$(echo "$request" | jq -r .email)
        password=$(echo "$request" | jq -r .password)
        role=$(echo "$request" | jq -r .role)
        firstName=$(echo "$request" | jq -r .firstName)
        lastName=$(echo "$request" | jq -r .lastName)
        note=$(echo "$request" | jq -r .note)
        log "Performing user '$op' for user '$email' with firstname '$firstName', lastname '$lastName', note '$note' and role '$role'"
        response=$(echo "$password" | $CMD_PREFIX so-user "$op" --email "$email" --firstName "$firstName" --lastName "$lastName" --note "$note" --role "$role" --skip-sync)
        exit_code=$?
        ;;
      add|enable|disable|delete)
        email=$(echo "$request" | jq -r .email)
        log "Performing user '$op' for user '$email'"
        response=$($CMD_PREFIX so-user "$op" --email "$email" --skip-sync)
        exit_code=$?
        ;;
      addrole|delrole)
        email=$(echo "$request" | jq -r .email)
        role=$(echo "$request" | jq -r .role)
        log "Performing '$op' for user '$email' with role '$role'"
        response=$($CMD_PREFIX so-user "$op" --email "$email" --role "$role" --skip-sync)
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
        response=$($CMD_PREFIX so-user "$op" --email "$email" --firstName "$firstName" --lastName "$lastName" --note "$note")
        exit_code=$?
        ;;
      sync)
        log "Performing '$op'"
        response=$($CMD_PREFIX so-user "$op")
        exit_code=$?
        ;;
      *)
        response="Unsupported user operation: $op"
        exit_code=1
        ;;
    esac

    tries=$((tries+1))
    if [[ "$response" == "Another process is using so-user"* ]]; then
      log "Retrying after brief delay to let so-user unlock ($tries/$max_tries)"
      sleep 5
    else
      break
    fi
  done

  if [[ exit_code -eq 0 ]]; then
    log "Successful command execution: $response"
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
  if [[ -s $minion || "$minion" == "null" ]]; then
    minion=$(cat /etc/salt/minion | grep "id:" | awk '{print $2}' | sed "s/'//g")
  fi

  case "$op" in
    state)
      log "Performing '$op' for '$state' on minion '$minion'"
      state=$(echo "$request" | jq -r .state)
      response=$($CMD_PREFIX salt --async "$minion" state.apply "$state" queue=2)
      exit_code=$?
      ;;
    highstate)
      log "Performing '$op' on minion $minion"
      response=$($CMD_PREFIX salt --async "$minion" state.highstate queue=2)
      exit_code=$?
      ;;
    activejobs)
      response=$($CMD_PREFIX salt-run jobs.active -out json -l quiet)
      log "Querying active salt jobs"
      $(echo "$response" > "${SOC_PIPE}")
      return
      ;;
    *)
      response="Unsupported salt operation: $op"
      exit_code=1
      ;;
  esac

  if [[ exit_code -eq 0 ]]; then
    log "Successful command execution: $response"
    $(echo "true" > "${SOC_PIPE}")
  else
    log "Unsuccessful command execution: $response ($exit_code)"
    $(echo "false" > "${SOC_PIPE}")
  fi
}

function send_file() {
  request=$1
  from=$(echo "$request" | jq -r .from)
  to=$(echo "$request" | jq -r .to)
  node=$(echo "$request" | jq -r .node)
  [ $(echo "$request" | jq -r .cleanup) != "true" ] ; cleanup=$?

  log "From: $from"
  log "To: $to"
  log "Node: $node"
  log "Cleanup: $cleanup"

  log "encrypting..."
  gpg --passphrase "infected" --batch --symmetric --cipher-algo AES256 "$from"

  fromgpg="$from.gpg"

  log "sending..."
  response=$($CMD_PREFIX salt-cp -C "$node" "$fromgpg" "$to")
  exit_code=$?

  rm -f "$fromgpg"

  log Response:$'\n'"$response"
  log "Exit Code: $exit_code"

  if [[ exit_code -eq 0 ]]; then
    if [[ $cleanup -eq 1 ]]; then
      log "Cleaning up file $from"
      rm -f "$from"
    fi
    $(echo "true" > "${SOC_PIPE}")
  else
    $(echo "false" > "${SOC_PIPE}")
  fi
}

function import_file() {
  request=$1
  node=$(echo "$request" | jq -r .node)
  file=$(echo "$request" | jq -r .file)
  importer=$(echo "$request" | jq -r .importer)

  log "Node: $node"
  log "File: $file"
  log "Importer: $importer"

  filegpg="$file.gpg"

  log "decrypting..."
  gpg --passphrase "infected" --batch --decrypt "$filegpg" > "$file"

  log "importing..."
  case $importer in
    pcap)
      response=$($CMD_PREFIX "salt '$node' cmd.run 'so-import-pcap $file'")
      exit_code=$?
      ;;
    evtx)
      response=$($CMD_PREFIX "salt '$node' cmd.run 'so-import-evtx $file'")
      exit_code=$?
      ;;
    *)
      response="Unsupported importer: $importer"
      exit_code=1
      ;;
  esac

  rm "$file" "$filegpg"

  log Response:$'\n'"$response"
  log "Exit Code: $exit_code"

  if [[ exit_code -eq 0 ]]; then
    url=$(echo "$response" | sed ':a;N;$!ba;s/\n//g' | grep -E -o "https://\S*")
    $(echo "$url" > "${SOC_PIPE}")
  else
    log "false"
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
      send-file)
        send_file "${request}"
        ;;
      import-file)
        import_file "${request}"
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
