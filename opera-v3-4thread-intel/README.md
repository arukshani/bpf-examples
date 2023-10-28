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
sudo taskset --cpu-list 1 -s 192.168.1.2 -p 5000  

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
For AMD
GRUB_CMDLINE_LINUX_DEFAULT="init_on_alloc=0 amd_iommu=off"
init_on_alloc=0 amd_iommu=off
sudo update-grub
cat /sys/class/net/veth0/queues/rx-0/rps_cpus
cat /sys/class/net/veth1/queues/rx-0/rps_cpus
echo 00010000 | tee /sys/class/net/veth0/queues/rx-0/rps_cpus
echo 00010000 | sudo tee /sys/class/net/veth1/queues/rx-0/rps_cpus
echo 00000002 | tee /sys/class/net/veth0/queues/rx-0/rps_cpus
echo 00000002 | sudo tee /sys/class/net/veth1/queues/rx-0/rps_cpus

echo 00010000 | tee /sys/class/net/veth0/queues/tx-0/xps_cpus

echo 00000010 | sudo tee /sys/class/net/enp65s0f0np0/queues/rx-0/rps_cpus

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

```
wget https://content.mellanox.com/ofed/MLNX_OFED-5.8-3.0.7.0/MLNX_OFED_LINUX-5.8-3.0.7.0-ubuntu22.04-x86_64.tgz

cat /proc/interrupts | grep enp65s0f0np0
cat /proc/irq/154/smp_affinity
echo 00000008 | sudo tee /proc/irq/154/smp_affinity

sudo service irqbalance stop
```

```
For intel
GRUB_CMDLINE_LINUX_DEFAULT="init_on_alloc=0 intel_iommu=off"

NUMA:
  NUMA node(s):          2
  NUMA node0 CPU(s):     0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62,64,66,68,70,72,74,76,78,80,82,84,86,88,90,92,94,96,98,100,102,104,106,108,110,112,114,11
                         6,118,120,122,124,126,128,130,132,134,136,138,140,142
  NUMA node1 CPU(s):     1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83,85,87,89,91,93,95,97,99,101,103,105,107,109,111,113,115,11
                         7,119,121,123,125,127,129,131,133,135,137,139,141,143

cat /sys/class/net/enp202s0f0np0/device/numa_node


sudo taskset --cpu-list 19 ./opera_v4_timing 192.168.1.1 configs/node-1-link.csv /dev/ptp0 120
sudo taskset --cpu-list 19 ./opera_v4_timing 192.168.1.2 configs/node-2-link.csv /dev/ptp0 120
taskset --cpu-list 3 iperf3 -c 192.168.1.2 -p 5000 -t 120
taskset --cpu-list 3 iperf3 -s 192.168.1.2 -p 5000

AF_XDP - Core 21, 23, 25, 27

echo 0000,00000000,00000000,00000000,00000000 | tee /sys/class/net/veth0/queues/rx-0/rps_cpus 
echo 0000,00000000,00000000,00000000,00000000 | sudo tee /sys/class/net/veth1/queues/rx-0/rps_cpus

```