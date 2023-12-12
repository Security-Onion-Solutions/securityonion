#!/bin/bash
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

. /usr/sbin/so-common

QUEUE_OWNER=${QUEUE_OWNER:-socore}
QUEUE_GROUP=${QUEUE_GROUP:-socore}
MIN_POLL_INTERVAL=${MIN_POLL_INTERVAL:-1}
LOG_FILE=${LOG_FILE:-/opt/so/log/soc/salt-relay.log}
PATH=${PATH}:/usr/sbin

# USE CAUTION when changing this value as all files in this dir will be deleted
QUEUE_DIR=/opt/so/conf/soc/queue

function log() {
  echo "$(date) | $1" >> $LOG_FILE
}

function poll() {
  # Purge any expired files older than 1 minute. SOC will have already errored out to the user
  # if a response hasn't been detected by this time.
  find "$QUEUE_DIR" -type f -mmin +1 -delete

  file=$(ls -1trI "*.response" "$QUEUE_DIR" | head -1)
  if [[ "$file" != "" ]]; then
    contents=$(cat "$QUEUE_DIR/$file")
    # Delete immediately to prevent a crash from potentially causing the same
    # command to be executed multiple times -> Safer to not run at all than to
    # potentially execute multiple times (Ex: user management)
    rm -f "$QUEUE_DIR/$file"
    echo "$contents"
  fi
}

function respond() {
  file="$QUEUE_DIR/$1.response"
  tmpfile="${file}.tmp"
  response=$2

  touch "$tmpfile"
  chmod 660 "$tmpfile"
  chown "$QUEUE_OWNER:$QUEUE_GROUP" "$tmpfile"
  echo "$response" > "$tmpfile"
  mv $tmpfile $file
}

function list_minions() {
  id=$1
  response=$(so-minion -o=list)
  exit_code=$?
  if [[ $exit_code -eq 0 ]]; then
    log "Successful command execution"
    respond "$id" "$response"
  else
    log "Unsuccessful command execution: $exit_code"
    respond "$id" "false"
  fi
}

function manage_minion() {
  id=$1
  request=$2
  op=$(echo "$request" | jq -r .operation)
  minion_id=$(echo "$request" | jq -r .id)

  response=$(so-minion "-o=$op" "-m=$minion_id")
  exit_code=$?
  if [[ exit_code -eq 0 ]]; then
    log "Successful '$op' command execution on $minion_id"
    respond "$id" "true"
  else
    log "Unsuccessful '$op' command execution on $minion_id: $response ($exit_code)"
    respond "$id" "false"
  fi
}

function manage_user() {
  id=$1
  request=$2
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
    respond "$id" "true"
  else
    log "Unsuccessful command execution: $response ($exit_code)"
    respond "$id" "false"
  fi
}

function manage_salt() {
  id=$1
  request=$2
  op=$(echo "$request" | jq -r .operation)
  minion=$(echo "$request" | jq -r .minion)
  if [[ -s $minion || "$minion" == "null" ]]; then
    minion=$(cat /etc/salt/minion | grep "id:" | awk '{print $2}' | sed "s/'//g")
  fi

  case "$op" in
    state)
      log "Performing '$op' for '$state' on minion '$minion'"
      state=$(echo "$request" | jq -r .state)
      response=$(salt --async "$minion" state.apply "$state" queue=2)
      exit_code=$?
      ;;
    highstate)
      log "Performing '$op' on minion $minion"
      response=$(salt --async "$minion" state.highstate queue=2)
      exit_code=$?
      ;;
    activejobs)
      response=$(salt-run jobs.active -out json -l quiet)
      log "Querying active salt jobs"
      respond "$id" "$response"
      return
      ;;
    *)
      response="Unsupported salt operation: $op"
      exit_code=1
      ;;
  esac

  if [[ exit_code -eq 0 ]]; then
    log "Successful command execution: $response"
    respond "$id" "true"
  else
    log "Unsuccessful command execution: $response ($exit_code)"
    respond "$id" "false"
  fi
}

function send_file() {
  id=$1
  request=$2
  from=$(echo "$request" | jq -r .from)
  to=$(echo "$request" | jq -r .to)
  node=$(echo "$request" | jq -r .node)
  [ $(echo "$request" | jq -r .cleanup) != "true" ] ; cleanup=$?

  log "From: $from"
  log "To: $to"
  log "Node: $node"
  log "Cleanup: $cleanup"

  log "encrypting..."
  password=$(lookup_pillar_secret import_pass)
  response=$(gpg --passphrase "$password" --batch --symmetric --cipher-algo AES256 "$from")
  log Response:$'\n'"$response"

  fromgpg="$from.gpg"
  filename=$(basename "$fromgpg")

  log "sending..."
  response=$(salt-cp -C "$node" "$fromgpg" "$to")
  # salt-cp returns 0 even if the file transfer fails, so we need to check the response.
  # Remove the node and filename from the response on the off-chance they contain
  # the word "True" in them
  echo $response | sed "s/$node//" | sed "s/$filename//" | grep True
  exit_code=$?

  rm -f "$fromgpg"

  log Response:$'\n'"$response"
  log "Exit Code: $exit_code"

  if [[ $cleanup -eq 1 ]]; then
    log "Cleaning up file $from"
    rm -f "$from"
  fi

  if [[ exit_code -eq 0 ]]; then
    respond "$id" "true"
  else
    respond "$id" "false"
  fi
}

function import_file() {
  id=$1
  request=$2
  node=$(echo "$request" | jq -r .node)
  file=$(echo "$request" | jq -r .file)
  importer=$(echo "$request" | jq -r .importer)

  log "Node: $node"
  log "File: $file"
  log "Importer: $importer"

  filegpg="$file.gpg"

  log "decrypting..."
  password=$(lookup_pillar_secret import_pass)
  decrypt_cmd="gpg --passphrase $password -o $file.tmp --batch --decrypt $filegpg"
  salt "$node" cmd.run "\"$decrypt_cmd\""
  decrypt_code=$?

  if [[ $decrypt_code -eq 0 ]]; then
    mv "$file.tmp" "$file"
    log "importing..."
    case $importer in
      pcap)
        import_cmd="so-import-pcap $file --json"
        response=$(salt "$node" cmd.run "\"$import_cmd\"")
        exit_code=$?
        ;;
      evtx)
        import_cmd="so-import-evtx $file --json"
        response=$(salt "$node" cmd.run "\"$import_cmd\"")
        exit_code=$?
        ;;
      *)
        response="Unsupported importer: $importer"
        exit_code=1
        ;;
    esac
  else
    response="Failed to decrypt file: $file"
    exit_code=$decrypt_code
  fi

  rm -f "$file" "$filegpg"

  log Response:$'\n'"$response"
  log "Exit Code: $exit_code"

  if [[ exit_code -eq 0 ]]; then
    # trim off the node header ("manager_standalone:\n") and parse out the URL
    url=$(echo "$response" | tail -n +2 | jq -r .url)
    respond "$id" "$url"
  else
    log "false"
    respond "$id" "false"
  fi
}

# Ensure there are not multiple salt-relay.sh programs running.
num_relays_running=$(pgrep salt-relay.sh -c)
if [[ $num_relays_running -gt 1 ]]; then
  exit;
fi

# loop indefinitely
log "Polling for requests: ${QUEUE_DIR}"
while true; do
  request=$(poll)
  if [[ "$request" != "" ]]; then
    command=$(echo "$request" | jq -r .command)
    id=$(echo "$request" | jq -r .command_id)
    log "Received request; command=${command}; id=${id}"
    case "$command" in
      list-minions)
        list_minions "$id" 
        ;;
      manage-minion)
        manage_minion "$id" "${request}"
        ;;
      manage-user)
        manage_user "$id" "${request}"
        ;;
      manage-salt)
        manage_salt "$id" "${request}"
        ;;
      send-file)
        send_file "$id" "${request}"
        ;;
      import-file)
        import_file "$id" "${request}"
        ;;
      *)
        log "Unsupported command: $command"
        respond "$id" "false"
        ;;
    esac
  fi
  sleep $MIN_POLL_INTERVAL
done
