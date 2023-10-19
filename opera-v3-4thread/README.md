### This is version 3 - Four Thread Implementation 

#### Indirection - opera_nic_indirection.c

```
sudo ip netns exec blue bash

sudo ./opera_nic_indirection 192.168.1.1 configs/node-1-link.csv /dev/ptp3 60
sudo ./opera_nic_indirection 192.168.1.2 configs/node-2-link.csv /dev/ptp3 60
sudo ./opera_nic_indirection 192.168.1.3 configs/node-3-link.csv /dev/ptp3 60

sudo ./opera_v4_timing 192.168.1.1 configs/node-1-link.csv /dev/ptp3 120
sudo ./opera_v4_timing 192.168.1.2 configs/node-2-link.csv /dev/ptp3 120

iperf3 -c 192.168.1.2 -p 5000  
iperf3 -s 192.168.1.2 -p 5000  

sudo taskset --cpu-list 1 iperf3 -c 192.168.1.2 -p 5000 -t 120

sudo ./opera_v4_counters 192.168.1.1 configs/node-1-link.csv /dev/ptp3 30
sudo ./opera_v4_counters 192.168.1.2 configs/node-2-link.csv /dev/ptp3 30

```

### Flame Graph
```
cd ~
sudo apt-get install flex
sudo apt-get install bison
wget  https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.15.99.tar.xz
tar -xf linux-5.15.99.tar.xz
cd linux-5.15.99/tools/perf
make
cd ~
ln -s linux-5.15.99/tools/perf/perf perf
testing -> sudo ./perf top -C 10
git clone https://github.com/brendangregg/FlameGraph.git

Generate flamegraph: ./perf_command_new.sh $core 
Change $core to the CPU core number you like to observe
Also, I see there are some cores CPU usage are not constant; maybe do: sudo perf top -C $core 
To see what happens inside the core.
```

```
init_on_alloc=0 amd_iommu=off
sudo update-grub
cat /sys/class/net/veth0/queues/rx-0/rps_cpus
echo 00010000 | tee /sys/class/net/veth0/queues/rx-0/rps_cpus
```

```
01000000 - 24th core
02000000 - 25th core
04000000 - 26th core
08000000 - 27th core
0f000000 - 24,25,26,27

00000004 - 2nd core
00000008 - 3rd core

00010000 - 16th core
0000000f - 0-3 cores
0000000e - 1-3 cores
```

