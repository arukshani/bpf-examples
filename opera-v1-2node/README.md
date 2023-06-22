### This is version 1 - Single Thread Implementation with 2 nodes

#### Run iperf inside the namespace
```
sudo ip netns exec blue bash

iperf3 -s 192.168.1.2 -p 5000
iperf3 -c 192.168.1.2 -p 5000
```

#### Start the opera nic on specific nodes (Use this only if you are not starting opera_nic from the controller node)
```
sudo ./opera_nic 192.168.1.1 configs/node-1-link.csv /dev/ptp3 60
sudo ./opera_nic 192.168.1.2 configs/node-2-link.csv /dev/ptp3 60
```

