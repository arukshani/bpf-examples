#!/bin/bash

#Get veth mac
VETH_MAC=$(sudo ip netns exec blue ifconfig veth0 | awk '/ether/ {print $2}')

#Get interface 
NODE_IN=$(ifconfig | grep -B1 "inet $1" | awk '$1!="inet" && $1!="--" {print $1}')
NODE_IN=${NODE_IN::-1}

#Get node mac
NODE_MAC=$(ip link show $NODE_IN | awk '/ether/ {print $2}')

echo $1,$NODE_IN,$NODE_MAC,$VETH_MAC



# sudo ip netns exec blue ifconfig | grep -B1 "inet 192.168.1.1" | awk '$1!="inet" && $1!="--" {print $1}'