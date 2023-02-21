#!/bin/bash

sudo ip netns add blue
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 netns blue
sudo ip netns exec blue ip link set dev veth0 up
sudo ip link set dev veth1 up

sudo ip netns exec blue ip addr add 192.168.1.2/24 dev veth0
sudo ip netns exec blue ip link set arp off dev veth0
