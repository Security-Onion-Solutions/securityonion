#!/bin/bash

. ../salt/common/tools/sbin/so-common

script_ret=0

GREEN="\e[1;32m"
RED="\e[1;31m"
RESET="\e[0m"

test_fun() {
  local expected_result=$1
  shift

  local fun=$1
  shift

  $fun "$@" 
  local ret=$?
  [[ $ret -eq 0 ]] && res="O" || res="X"

  [[ $ret -ne $expected_result ]] && script_ret=1

  local prefix=$1
  [[ -n $2 ]] && prefix="$prefix, min=$2"
  [[ -n $3 ]] && prefix="$prefix, max=$3"

  [[ $prefix == "" ]] && prefix="[EMPTY]"

  [[ $ret -eq $expected_result ]] \
    && printf "${GREEN}%b${RESET}" "  $res" \
    || printf "${RED}%b${RESET}" "  $res"
  
  printf "%s\n" " - $prefix"
}

header "FQDN"

test_fun 0 valid_fqdn "rwwiv.com"

test_fun 0 valid_fqdn "ddns.rwwiv.com"

test_fun 1 valid_fqdn ".com"

test_fun 1 valid_fqdn "rwwiv."

test_fun 1 valid_fqdn ""

sleep 0.15s

header "ip4"

test_fun 0 valid_ip4 "192.168.1.1"

test_fun 0 valid_ip4 "192.168.1.255"

test_fun 1 valid_ip4 "192.168.1.256"

test_fun 1 valid_ip4 "192.168..1"

test_fun 1 valid_ip4 "192.168.1.1."

test_fun 1 valid_ip4 ""

sleep 0.15s

header "CIDR (ipv4)"

test_fun 0 valid_cidr "192.168.1.0/24"

test_fun 0 valid_cidr "192.168.1.0/12"

test_fun 1 valid_cidr "192.168.1.0"

test_fun 1 valid_ip4 "192.168.1.0/"

test_fun 1 valid_ip4 "/24"

test_fun 1 valid_cidr ""

sleep 0.15s

header "CIDR list"

test_fun 0 valid_cidr_list "10.0.0.0/8,192.168.0.0/16,172.16.0.0/12"

test_fun 0 valid_cidr_list "10.0.0.0/8"

test_fun 1 valid_cidr_list "10.0.0.0/8,192.168.0.0/16172.16.0.0/12"

test_fun 1 valid_cidr_list "10.0.0.0"

sleep 0.15s

header "DNS"

test_fun 0 valid_dns_list "8.8.8.8,8.8.4.4"

test_fun 0 valid_dns_list "8.8.8.8"

test_fun 1 valid_dns_list "8.8.8.8 8.8.4.4"

test_fun 1 valid_dns_list "8.8.8.,8.8.4.4"

test_fun 1 valid_dns_list "192.168.9."

sleep 0.15s

header "int (default min: 1, default max: 1000)"

test_fun 0 valid_int "24"

test_fun 0 valid_int "1"

test_fun 0 valid_int "2" "2" 

test_fun 0 valid_int "1000"

test_fun 1 valid_int "10001"

test_fun 1 valid_int "24" "" "20"

test_fun 1 valid_int "-1"

test_fun 1 valid_int "1" "2"

test_fun 1 valid_int "257" "" "256"

test_fun 1 valid_int "not_a_num"

test_fun 1 valid_int ""

sleep 0.15s

header "hostname"

test_fun 0 valid_hostname "so-sensor01"

test_fun 0 valid_hostname "so"

test_fun 1 valid_hostname "so_sensor01"

test_fun 1 valid_hostname "so.sensor01"

test_fun 1 valid_hostname "localhost"

test_fun 1 valid_hostname ""

sleep 0.15s

header "string (default min_length: 1, default max_length: 64)"

test_fun 0 valid_string "string"

test_fun 0 valid_string "s"

test_fun 0 valid_string "very_long_string_64_sdhkjashasdfkajjagskfjhgkslfkjhlaskfhlaskjhf"

test_fun 0 valid_string "12"

test_fun 1 valid_string "string with spaces"

test_fun 1 valid_string "very_long_string_<64_sdhflkjashasdfkajshfgkjsahgfkjagskfjhgkslfkjhlaskfhlaskjhf"

test_fun 1 valid_string "too_short" "12"

test_fun 1 valid_string "too_long" "" "4"

test_fun 1 valid_string ""

sleep 0.15s

header "Linux user"

test_fun 0 valid_username "so_user_01"

test_fun 0 valid_username "onionuser"

test_fun 1 valid_username "12fa"

test_fun 1 valid_username "so.user.01"

test_fun 1 valid_username "very_long_username_asdflashfsafasdfasdfkahsgkjahfdkjhsg"

echo

exit $script_ret
