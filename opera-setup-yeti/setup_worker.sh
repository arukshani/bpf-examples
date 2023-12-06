#!/bin/sh

sudo apt-get -y update
# cd /opt
# git clone https://github.com/arukshani/bpf-examples.git 
# sudo apt-get -y install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
# sudo apt-get -y install linux-tools-$(uname -r)
# sudo apt-get -y install linux-headers-$(uname -r)
# sudo apt-get -y install linux-tools-common linux-tools-generic
# sudo apt-get -y install tcpdump
# sudo apt-get -y install jq
# sudo apt-get -y install linuxptp
# sudo apt-get -y install libmnl-dev
# sudo apt-get -y install m4
# sudo apt-get -y install iperf3
# sudo apt-get -y install htop

#Get interface 
# NODE_INTERFACE=$(ifconfig | grep -B1 "inet $1" | awk '$1!="inet" && $1!="--" {print $1}')
# NODE_INTERFACE=${NODE_INTERFACE::-1}
NODE_INTERFACE=ens4

echo 2| sudo tee /sys/class/net/$NODE_INTERFACE/napi_defer_hard_irqs
echo 1000 | sudo tee /sys/class/net/$NODE_INTERFACE/gro_flush_timeout

sudo ip netns add blue
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 netns blue
sudo ip netns exec blue ip link set dev veth0 up
sudo ip link set dev veth1 up
ip_addr=$(ip -f inet addr show $NODE_INTERFACE | awk '/inet / {print $2}')
sudo ip netns exec blue ip addr add $ip_addr dev veth0
sudo ip netns exec blue ip link set arp off dev veth0
sudo ip netns exec blue ethtool -K veth0 tx off
sudo ip netns exec blue ip link set veth0 mtu 3400
sudo ip link set $NODE_INTERFACE mtu 3490
sudo ip link set veth1 mtu 3400
sudo ethtool -L $NODE_INTERFACE combined 1

sudo ip netns add red
sudo ip link add veth2 type veth peer name veth3
sudo ip link set veth2 netns red
sudo ip netns exec red ip link set dev veth2 up
sudo ip link set dev veth3 up
ip_addr=$(ip -f inet addr show $NODE_INTERFACE | awk '/inet / {print $2}')
sudo ip netns exec red ip addr add $ip_addr dev veth2
sudo ip netns exec red ip link set arp off dev veth2
sudo ip netns exec red ethtool -K veth2 tx off
sudo ip netns exec red ip link set veth2 mtu 3400
sudo ip link set veth3 mtu 3400
