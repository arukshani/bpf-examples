### This is version 1 - Single Thread Implementation

```
sudo ip netns exec blue bash

sudo ./opera_nic 192.168.1.1 configs/node-1-link.csv /dev/ptp3 60
sudo ./opera_nic 192.168.1.2 configs/node-2-link.csv /dev/ptp3 60

iperf3 -s 192.168.1.2 -p 5000
iperf3 -c 192.168.1.2 -p 5000
```

