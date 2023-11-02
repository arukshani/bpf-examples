#!/bin/sh

#bash setup_veth.sh 192.168.1.1 (mention correct lan_ip here)

NODE_INTERFACE=$(ifconfig | grep -B1 "inet $1" | awk '$1!="inet" && $1!="--" {print $1}')
NODE_INTERFACE=${NODE_INTERFACE::-1}
echo $NODE_INTERFACE
ip_addr=$(ip -f inet addr show $NODE_INTERFACE | awk '/inet / {print $2}')
echo $ip_addr
sudo ip netns add red
sudo ip link add veth2 type veth peer name veth3
sudo ip link set veth2 netns red
sudo ip netns exec red ip link set dev veth2 up
sudo ip link set dev veth3 up
sudo ip netns exec red ip addr add $ip_addr dev veth2
sudo ip netns exec red ip link set arp off dev veth2
sudo ip netns exec red ethtool -K veth2 tx off
sudo ip netns exec red ip link set veth2 mtu 3400
sudo ip link set veth3 mtu 3400