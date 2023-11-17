### All Nodes
```
cd bpf-examples/opera-setup-yeti/
./setup_master.sh
```

### Setup IPs
```
sudo ip addr add 10.1.0.1/24 dev ens4
sudo ip addr add 10.1.0.2/24 dev ens4
ip link set dev ens4 up
```

### Worker things
```
./setup_worker.sh
```

### Write mac details to file
```
python3 setup_mac.py
```

### Add ARP records
```
python3 setup_arp.py "10.1.0.1"
python3 setup_arp.py "10.1.0.2"
```

### Update clang version to 11 if needed 
```
sudo apt-get install clang-11 libc++-11-dev libc++abi-11-dev
sudo su
cd /usr/lib/llvm-11/bin
for f in *; do rm -f /usr/bin/$f; \
    ln -s ../lib/llvm-11/bin/$f /usr/bin/$f; done
exit
clang --version
```

```
ns11
vethin12
vethout22
ns12
vethin13
vethout23
ns13
vethin14
vethout24
ns14
vethin15
vethout25
ns15
vethin16
vethout26
ns16
vethin17
vethout27
ns17
vethin18
vethout28
ns18
vethin19
vethout29
ns19
vethin20
vethout30
ns20
vethin21
vethout31
ns21
vethin22
vethout32
ns22
vethin23
vethout33
ns23
vethin24
vethout34
ns24
vethin25
vethout35
```

```
sudo ip netns del ns
ip netns list
sudo ip netns exec ns11 bash
iperf -c 10.1.0.2 -u -t 200 -b 50000M -i 1
```

```
(main)
n_ports = 9;

t->ports_rx[8] = ports[8]; // veth29

port_params[8].iface = "vethout29"; 
port_params[8].iface_queue = 0;

(thread_func_veth)
if (track_veth_rx_port == 8) {

(load_xdp_program)
struct config cfgs[9]

static struct xdp_program *xdp_prog[9];
```