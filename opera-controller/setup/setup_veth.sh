#!/bin/bash

sudo ip netns add blue
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 netns blue
sudo ip netns exec blue ip link set dev veth0 up
sudo ip link set dev veth1 up

ip_addr=$(ip -f inet addr show eno50np1 | awk '/inet / {print $2}')

sudo ip netns exec blue ip addr add $ip_addr dev veth0
sudo ip netns exec blue ip link set arp off dev veth0
sudo ip netns exec blue ethtool -K veth0 tx off
sudo ip netns exec blue ip link set veth0 mtu 3400

sudo ip link set eno50np1 mtu 3490
sudo ip link set veth1 mtu 3400

