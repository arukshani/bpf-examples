#!/bin/bash

sudo ip netns add red
sudo ip link add veth2 type veth peer name veth3
sudo ip link set veth2 netns red
sudo ip netns exec red ip link set dev veth2 up
sudo ip link set dev veth3 up

ip_addr=$(ip -f inet addr show enp65s0f0np0 | awk '/inet / {print $2}')

sudo ip netns exec red ip addr add $ip_addr dev veth2
sudo ip netns exec red ip link set arp off dev veth2
sudo ip netns exec red ethtool -K veth2 tx off
sudo ip netns exec red ip link set veth2 mtu 3400

sudo ip link set veth3 mtu 3400
