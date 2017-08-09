#!/bin/bash

BUTTERFLY_BUILD_ROOT=$1
BUTTERFLY_SRC_ROOT=$(cd "$(dirname $0)/../.." && pwd)
source $BUTTERFLY_SRC_ROOT/tests/functions.sh

network_connect 0 1
server_start 0
sg_rule_add_icmp 0 sg-1
nic_add 0 1 42 sg-1
nic_add 0 2 42 sg-1
qemus_start 1 2
ssh_ping 1 2
ssh_ping 2 1

server_stop 0
ssh_no_ping 1 2
ssh_no_ping 2 1

echo "read 1"
read

server_start 0
sg_rule_add_icmp 0 sg-1
nic_add 0 1 42 sg-1
nic_add 0 2 42 sg-1
echo "go"
read
sleep 10
ssh_ping 1 2
ssh_ping 2 1

qemus_stop 1 2
server_stop 0
network_disconnect 0 1
return_result
