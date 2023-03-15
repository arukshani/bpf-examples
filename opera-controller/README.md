```

ip -details link show veth0
ip -details link show eno50np1

ethtool -K veth0 tx off
ethtool -K veth0 tx off

sudo ip netns exec blue ip link set veth0 mtu 3900
sudo ip link set veth1 mtu 3900
sudo ip link set eno50np1 mtu 3950


iperf3 -s 192.168.1.2 -p 5000
iperf3 -c 192.168.1.2 -p 5000 

iperf3 -c 192.168.1.2 -p 5000 -M 2500  (5.94 Gbits/sec)

sudo ip link set eno50np1 mtu 3490
RTNETLINK answers: Invalid argument
ip link set veth0 mtu 3400 
sudo ip link set veth1 mtu 3400

iperf3 -c 192.168.1.2 -p 5000 (7.67 Gbits/sec)

//In client
arp -s 192.168.1.2 86:99:55:ab:89:0f

//In server
arp -s 192.168.1.1 fe:65:a9:a9:ad:64

arp -s 192.168.1.3 22:e8:7f:3c:c8:1b
```