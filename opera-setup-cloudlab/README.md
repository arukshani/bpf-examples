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
python3 setup_arp.py "10.1.0.1"
python3 setup_arp.py "10.1.0.2"
```

```
lscpu | grep NUMA
```