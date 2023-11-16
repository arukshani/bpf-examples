#!/bin/bash

NODE_IN=ens4
lan_addr=$(ip -f inet addr show ens4 | awk '/inet / {print substr($2, 1, length($2)-3)}')

#Get veth mac
VETH0_MAC=$(sudo ip netns exec blue ifconfig veth0 | awk '/ether/ {print $2}')
VETH2_MAC=$(sudo ip netns exec red ifconfig veth2 | awk '/ether/ {print $2}')

#Get interface 
# NODE_IN=$(ifconfig | grep -B1 "inet $lan_addr" | awk '$1!="inet" && $1!="--" {print $1}')
# NODE_IN=${NODE_IN::-1}

#Get node mac
NODE_MAC=$(ip link show $NODE_IN | awk '/ether/ {print $2}')

# IFS='.' read ip1 ip2 ip3 ip4 <<< "$lan_addr"
# PTP_IP=10.10.1.$ip4
# # echo $PTP_IP
# PTP_IN=$(ifconfig | grep -B1 "inet $PTP_IP" | awk '$1!="inet" && $1!="--" {print $1}')
# PTP_IN=${PTP_IN::-1}
PTP_IN=eno1

# enp65s0f0np0 /dev/ptp2
# enp65s0f1np1 /dev/ptp3

PTP_CLOCK="/dev/ptp0"

# if [[ $PTP_IN = "enp65s0f0np0" ]]; then
#     PTP_CLOCK="/dev/ptp2"
# elif [[ $PTP_IN = "enp65s0f1np1" ]]; then
#     PTP_CLOCK="/dev/ptp3"
# fi

echo $lan_addr,$NODE_IN,$NODE_MAC,$PTP_IN,$PTP_CLOCK,$VETH0_MAC,$VETH2_MAC

# sudo ip netns exec blue ifconfig | grep -B1 "inet 192.168.1.1" | awk '$1!="inet" && $1!="--" {print $1}'