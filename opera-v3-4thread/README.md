### This is version 3 - Four Thread Implementation 

#### Indirection - opera_nic_indirection.c

```
sudo ip netns exec blue bash

sudo ./opera_nic_indirection 192.168.1.1 configs/node-1-link.csv /dev/ptp3 60
sudo ./opera_nic_indirection 192.168.1.2 configs/node-2-link.csv /dev/ptp3 60
sudo ./opera_nic_indirection 192.168.1.3 configs/node-3-link.csv /dev/ptp3 60

sudo ./opera_v4_timing 192.168.1.1 configs/node-1-link.csv /dev/ptp3 60
sudo ./opera_nic_indirection 192.168.1.2 configs/node-2-link.csv /dev/ptp3 60

iperf3 -c 192.168.1.2 -p 5000  
iperf3 -s 192.168.1.2 -p 5000     

```

