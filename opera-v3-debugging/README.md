### This is version 3 - Four Thread Implementation 

#### Indirection - opera_nic_indirection.c

```
sudo ip netns exec blue bash

```

```
cd /home/dathapathu/emulator/github_code/bpf-examples/opera-v3-multiveth-yeti

iperf3 -c 10.1.0.2 -p 5000  
iperf3 -s 10.1.0.2 -p 5000 

sudo ./opera_v4_timing 10.1.0.1 configs/node-1-link.csv /dev/ptp0 120
sudo ./opera_v4_timing 10.1.0.2 configs/node-2-link.csv /dev/ptp0 120


sudo taskset --cpu-list 17 ./opera_v4_timing 10.1.0.1 configs/node-1-link.csv /dev/ptp0 120
sudo taskset --cpu-list 17 ./opera_v4_timing 10.1.0.2 configs/node-2-link.csv /dev/ptp0 120
sudo taskset --cpu-list 3 iperf3 -c 10.1.0.2 -p 5000 -t 120
sudo taskset --cpu-list 3 iperf3 -s 10.1.0.2 -p 5000

sudo taskset --cpu-list 21 iperf3 -c 10.1.0.2 -p 3333 -t 120
sudo taskset --cpu-list 21 iperf3 -s 10.1.0.2 -p 3333

netperf -t UDP_STREAM -H 10.1.0.2 -l 2 -f g
netserver 
netperf -t UDP_STREAM -l 10 -f g -D 1

iperf -c 10.1.0.2 -u -t 10 -b 50000m -M 3000

iperf -c 10.1.0.2 -u -t 10 -b 50000M -M 3000 -i 1
iperf -c 10.1.0.2 -u -t 10 -b 50000M -i 1

iperf -c 10.1.0.2 -u -t 60 -b 50000M -i 1
iperf -s 10.1.0.2 -u

sudo ip netns exec blue iperf -c 10.1.0.2 -u -t 100 -b 50000M -i 1

```

```
./iperf_udp_blast.sh -n 0 (0 means one namespace, 1 means 2 namespaces)
sudo ./p2_drop 10.1.0.1 configs/node-1-link.csv /dev/ptp0 100 1
```

```
p2_drop - Recycle packets after receiving from VETH
p3_drop - Recycle packets after receiveing from per dest queues but before sending out it out via TX
p4_send - No drops; Just forward packets from veth to NIC (1 hardware NIC queue)
p5_rcv_drop - receive packets from NIC and recycle
```

```
sudo ./p4_send 10.1.0.1 configs/node-1-link.csv /dev/ptp0 80 1
sudo ./p5_rcv_drop 10.1.0.2 configs/node-2-link.csv /dev/ptp0 80 1
./iperf_udp_blast.sh -n 0
iperf -c 10.1.0.2 -u -t 60 -b 50000M -i 1

./iperf_udpblast_client_root.sh -n 1
./iperf_udpblast_server_root.sh -n 1

./iperf_tcp_client_root.sh -n 1
./iperf_tcp_server_root.sh -n 1

sudo ./iperf_udp_ns_server.sh -n 1
sudo ./iperf_udp_ns_client.sh -n 1

sudo ./opera_multi_nicq 10.1.0.1 configs/node-1-link.csv /dev/ptp0 100 1
sudo ./opera_multi_nicq 10.1.0.2 configs/node-2-link.csv /dev/ptp0 100 1

sudo ethtool -L ens4 combined 1


sudo ./p6_rcv_nodrop 10.1.0.1 configs/node-1-link.csv /dev/ptp0 120 1
sudo ./p6_rcv_nodrop 10.1.0.2 configs/node-2-link.csv /dev/ptp0 120 1
```
