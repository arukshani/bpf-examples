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

sudo ./iperf_udp_ns_server.sh -n 0
sudo ./iperf_udp_ns_client.sh -n 0

sudo ./iperf_tcp_ns_server.sh -n 0
sudo ./iperf_tcp_ns_client.sh -n 0
sudo ./mp_iperf_tcp_ns_client.sh -n 0

sudo ./opera_multi_nicq 10.1.0.1 configs/node-1-link.csv /dev/ptp0 100 1
sudo ./opera_multi_nicq 10.1.0.2 configs/node-2-link.csv /dev/ptp0 100 1

sudo ethtool -L ens4 combined 1


sudo ./p6_rcv_nodrop 10.1.0.1 configs/node-1-link.csv /dev/ptp0 80 1
sudo ./p6_rcv_nodrop 10.1.0.2 configs/node-2-link.csv /dev/ptp0 80 1

sudo ./nic_multi_q 10.1.0.1 configs/node-1-link.csv /dev/ptp0 120 3 1 (number of namespaces, number of nic queues)
sudo ./veth_tx_multi_thread 10.1.0.2 configs/node-2-link.csv /dev/ptp0 120 3 1

sudo ./scenario_2 10.1.0.1 configs/node-1-link.csv /dev/ptp0 120 1 1
sudo ./scenario_2 10.1.0.2 configs/node-2-link.csv /dev/ptp0 120 1 1

cd /home/dathapathu/emulator/github_code/bpf-examples/opera-v4-debug
cd /home/dathapathu/emulator/github_code/bpf-examples/opera-test-tools

sudo ethtool -L ens4 combined 1

sudo taskset --cpu-list 11 ./no_desc_buf 10.1.0.1 configs/node-1-link.csv /dev/ptp0 120 1 1 
sudo taskset --cpu-list 11 ./no_desc_buf 10.1.0.2 configs/node-2-link.csv /dev/ptp0 120 1 1

sudo taskset --cpu-list 15 ./cloud_intel 192.168.1.1 configs/node-1-link.csv /dev/ptp0 120 1 1 
sudo taskset --cpu-list 15 ./cloud_intel 192.168.1.2 configs/node-2-link.csv /dev/ptp0 120 1 1 
```


### IN case you want to remove xdp program from NIC driver
```
sudo ip link set ens4 xdpgeneric off
```

```

ethtool -K ens4 ntuple on 

ethtool --show-ntuple ens4

sudo ethtool -U ens4 flow-type tcp4 dst-port 5100 action 0
sudo ethtool -U ens4 flow-type tcp4 dst-port 5101 action 1
sudo ethtool -U ens4 flow-type tcp4 dst-port 5102 action 2
sudo ethtool -U ens4 flow-type tcp4 dst-port 5103 action 3
sudo ethtool -U ens4 flow-type tcp4 dst-port 5104 action 4

sudo ethtool -U ens4 delete 1019



lstopo
lstopo --output-format png -v > cpu-yeti.png

sudo ethtool -G ens4 rx 2048
sudo ethtool -G ens4 tx 2048
sudo ethtool -g ens4

apt-get install libpython2.7
sudo apt-get install libatlas3-base

```