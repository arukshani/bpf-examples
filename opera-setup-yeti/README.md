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

