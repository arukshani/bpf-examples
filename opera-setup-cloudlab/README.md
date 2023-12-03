### All Nodes
```
cd bpf-examples/opera-setup-cloudlab/
./setup_master.sh
```

### Worker things
```
./setup_worker.sh
./create_multi_ns.sh
```

### Write mac details to file
```
python3 setup_mac.py
```

### Copy reacords of other nodes to all_worker_info.csv

### Add ARP records
```
sudo ./get_veth_info.sh -n 13
scp arp records
python3 setup-arp.py filename


sudo ./set_irq_affinity.sh enp202s0f0np0

```

```
lscpu | grep NUMA
```