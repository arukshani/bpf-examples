#!/bin/sh

sudo apt-get -y update
cd /opt
git clone https://github.com/arukshani/bpf-examples.git 
sudo apt-get -y install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
sudo apt-get -y install linux-tools-$(uname -r)
sudo apt-get -y install linux-headers-$(uname -r)
sudo apt-get -y install linux-tools-common linux-tools-generic
sudo apt-get -y install tcpdump
sudo apt-get -y install jq
sudo apt-get -y install linuxptp
sudo apt-get -y install libmnl-dev
sudo apt-get -y install m4
sudo apt-get -y install iperf3
echo 2| sudo tee /sys/class/net/enp65s0f0np0/napi_defer_hard_irqs
echo 1000 | sudo tee /sys/class/net/enp65s0f0np0/gro_flush_timeout

sudo ip netns add blue
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 netns blue
sudo ip netns exec blue ip link set dev veth0 up
sudo ip link set dev veth1 up
ip_addr=$(ip -f inet addr show enp65s0f0np0 | awk '/inet / {print $2}')
sudo ip netns exec blue ip addr add $ip_addr dev veth0
sudo ip netns exec blue ip link set arp off dev veth0
sudo ip netns exec blue ethtool -K veth0 tx off
sudo ip netns exec blue ip link set veth0 mtu 3400
sudo ip link set enp65s0f0np0 mtu 3490
sudo ip link set veth1 mtu 3400
sudo ethtool -L enp65s0f0np0 combined 1


