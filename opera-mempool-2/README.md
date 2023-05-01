sudo ip netns exec blue bash

sudo ptp4l -i enp65s0f1np1 -m
sudo ptp4l -i enp65s0f0np0 -m

iperf3 -s 192.168.1.2 -p 5000
iperf3 -c 192.168.1.2 -p 5000

Wrong version