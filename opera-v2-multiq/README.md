### This is version 2 - Two Thread Implementation 

#### With multi-queue pause - opera_nic_multi_q.c
#### Receiver with no pause - opera_nic_receiver.c

```
sudo ip netns exec blue bash

sudo ./opera_nic_q 192.168.1.1 configs/node-1-link.csv /dev/ptp3 60
sudo ./opera_nic_q 192.168.1.2 configs/node-2-link.csv /dev/ptp3 60

sudo ./opera_nic_q 192.168.1.1 configs/node-1-link.csv /dev/ptp3 120
sudo ./opera_nic_q 192.168.1.3 configs/node-3-link.csv /dev/ptp3 120

iperf3 -s 192.168.1.3 -p 5000
iperf3 -c 192.168.1.3 -p 5000 -t 3

tcpdump -i veth0 -s 65535 -w test1.pcap
```

```
iperf3 -s 192.168.1.2 -p 5000
iperf3 -s 192.168.1.3 -p 5000

sudo ./opera_nic_multi_q 192.168.1.1 configs/node-1-link.csv /dev/ptp2 120
sudo ./opera_nic_receiver 192.168.1.2 configs/node-2-link.csv /dev/ptp3 120
sudo ./opera_nic_receiver 192.168.1.3 configs/node-3-link.csv /dev/ptp3 120

iperf3 -c 192.168.1.2 -p 5000 -t 3
iperf3 -c 192.168.1.3 -p 5000 -t 3

```

